// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/v75/github"
	"github.com/palantir/go-githubapp/githubapp"
	"github.com/rs/zerolog"

	"github.com/cilium/ariane/internal/config"
	"github.com/cilium/ariane/internal/log"
)

var configGetArianeConfigFromRepository = config.GetArianeConfigFromRepository

type PRCommentHandler struct {
	githubapp.ClientCreator
	RunDelay time.Duration
}

func (h *PRCommentHandler) Handles() []string {
	return []string{"issue_comment"}
}

func (h *PRCommentHandler) Handle(ctx context.Context, eventType, deliveryID string, payload []byte) error {
	var event github.IssueCommentEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return fmt.Errorf("failed to parse issue_comment event payload: %w", err)
	}

	// only handle PR comments, not issue comments
	if !event.GetIssue().IsPullRequest() {
		zerolog.Ctx(ctx).Debug().Msg("Issue comment event is not for a pull request")
		return nil
	}

	installationID := githubapp.GetInstallationIDFromEvent(&event)
	repository := event.GetRepo()
	prNumber := event.GetIssue().GetNumber()
	ctx, logger := githubapp.PreparePRContext(ctx, installationID, repository, prNumber)
	ctx = log.WithLogger(ctx, &logger)

	// only handle new comments
	logger.Debug().Msgf("Event action is %s", event.GetAction())
	if event.GetAction() != "created" {
		return nil
	}

	client, err := h.NewInstallationClient(installationID)
	if err != nil {
		return err
	}

	repositoryOwner := repository.GetOwner().GetLogin()
	repositoryName := repository.GetName()
	commentID := event.GetComment().GetID()
	commentAuthor := event.GetComment().GetUser().GetLogin()
	commentBody := event.GetComment().GetBody()

	var botUser bool

	// only handle non-bot comments
	if strings.HasSuffix(commentAuthor, "[bot]") {
		if !strings.HasPrefix(commentAuthor, repositoryOwner) {
			logger.Debug().Msgf("Issue comment was created by an unsupported bot: %s", commentAuthor)
			return nil
		}
		// comment created by the cilium-* [bot]
		botUser = true
	}

	// Get PR metadata and validate PR author permissions
	pr, err := h.getPullRequest(ctx, client, repositoryOwner, repositoryName, prNumber, logger)
	if err != nil {
		return err
	}

	contextRef, SHA := h.determineContextRef(pr, repositoryOwner, repositoryName, logger)

	// retrieve Ariane configuration (triggers, etc.) from repository based on chosen context
	arianeConfig, err := configGetArianeConfigFromRepository(client, ctx, repositoryOwner, repositoryName, contextRef)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to retrieve config file")
		return err
	}

	// only handle comments coming from an allowed organization, if specified
	if !botUser && !h.isAllowedTeamMember(ctx, client, arianeConfig, repositoryOwner, commentAuthor, logger) {
		// TODO It would be beneficial to provide feedback indicating that the test run was rejected.
		// Initially considered updating the comment with a "no entry" emoji, but given the limited
		// selection of emojis that can be used, none appeared to be entirely fitting.
		// Maybe alternative feedback mechanisms should be explored to communicate the rejection status clearly.
		return nil
	}

	// only handle comments matching a registered trigger, and retrieve associated list of workflows to trigger
	submatch, workflowsToTrigger := arianeConfig.CheckForTrigger(ctx, commentBody)
	// the command on commentBody (e.g. /test-this) does not match any "triggers"
	if submatch == nil {
		return nil
	}
	logger.Debug().Msgf("Found trigger phrase: %q", submatch)
	workflowDispatchEvent := h.createWorkflowDispatchEvent(prNumber, contextRef, SHA, submatch)

	files, err := h.getPRFiles(ctx, client, repositoryOwner, repositoryName, prNumber, logger)
	if err != nil {
		return err
	}

	for _, workflow := range workflowsToTrigger {
		if h.shouldSkipWorkflow(ctx, client, repositoryOwner, repositoryName, workflow, SHA, logger) {
			continue
		}

		if h.shouldRunWorkflow(ctx, arianeConfig, workflow, files) {
			if err := h.triggerWorkflow(ctx, client, repositoryOwner, repositoryName, workflow, workflowDispatchEvent, logger); err != nil {
				return err
			}
		} else {
			if err := h.markWorkflowAsSkipped(ctx, client, repositoryOwner, repositoryName, workflow, SHA, logger); err != nil {
				return err
			}
		}
	}

	if err := h.reactToComment(ctx, client, repositoryOwner, repositoryName, commentID, logger); err != nil {
		return err
	}

	return nil
}

// getPullRequest returns a PR object to retrieve a pull request metadata
func (h *PRCommentHandler) getPullRequest(ctx context.Context, client *github.Client, owner, repo string, prNumber int, logger zerolog.Logger) (*github.PullRequest, error) {
	opt := &github.PullRequestListOptions{
		State: "open",
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}
	for {
		prs, res, err := client.PullRequests.List(ctx, owner, repo, opt)
		if err != nil {
			logger.Error().Err(err).Msgf("Failed to retrieve pull request")
			return nil, err
		}

		for i := range prs {
			if prs[i].Number != nil && *prs[i].Number == prNumber {
				return prs[i], nil
			}
		}

		if res.NextPage == 0 {
			break
		}
		opt.ListOptions.Page = res.NextPage
	}
	err := errors.New("pull request not found")
	logger.Error().Msgf("%s", err.Error())
	return nil, err
}

func (h *PRCommentHandler) determineContextRef(pr *github.PullRequest, owner, repo string, logger zerolog.Logger) (string, string) {
	SHA := pr.GetHead().GetSHA()
	prOwner := pr.GetHead().GetRepo().GetOwner().GetLogin()
	prRepo := pr.GetHead().GetRepo().GetName()

	var contextRef string
	// PR comes from a fork
	if prOwner != owner || prRepo != repo {
		contextRef = pr.GetBase().GetRef()
		logger.Debug().Msgf("PR is from a fork, workflows for %s will run in the context of the PR target branch %s", SHA, contextRef)
	} else {
		contextRef = pr.GetHead().GetRef()
		logger.Debug().Msgf("PR is not from a fork, workflows for %s will run in the context of the PR branch %s", SHA, contextRef)
	}
	return contextRef, SHA
}

// isAllowedTeamMember uses the "Get team membership for a user" to infer if a user can run Ariane
// See https://docs.github.com/en/rest/teams/members?apiVersion=2022-11-28#get-team-membership-for-a-user
func (h *PRCommentHandler) isAllowedTeamMember(ctx context.Context, client *github.Client, config *config.ArianeConfig, owner, author string, logger zerolog.Logger) bool {
	// No list of allowed teams translate into everyone is allowed
	if len(config.AllowedTeams) == 0 {
		return true
	}

	for _, teamName := range config.AllowedTeams {
		membership, res, err := client.Teams.GetTeamMembershipBySlug(ctx, owner, teamName, author)
		if err != nil && (res == nil || res.StatusCode != 404) {
			logger.Error().Err(err).Msgf("Failed to retrieve issue comment author's membership to allowlist orgs/teams")
			return false
		}
		if res.StatusCode == 404 || membership.GetState() != "active" {
			logger.Debug().Msgf("User %s is not an (active) member of the team %s", author, teamName)
			continue
		}
		return true
	}
	return false
}

// Creates a reference for a workflow, in order to run it via workflow_dispatch
func (h *PRCommentHandler) createWorkflowDispatchEvent(prNumber int, contextRef, SHA string, submatch []string) github.CreateWorkflowDispatchEventRequest {
	workflowDispatchEvent := github.CreateWorkflowDispatchEventRequest{
		Ref: contextRef,
		// These are parameters (inputs) on workflow_dispatch
		Inputs: map[string]interface{}{
			"PR-number":   strconv.Itoa(prNumber),
			"context-ref": contextRef,
			"SHA":         SHA,
		},
	}

	if len(submatch) > 1 {
		extraArgs, err := json.Marshal(submatch[1])
		if err == nil {
			workflowDispatchEvent.Inputs["extra-args"] = string(extraArgs)
		}
	}
	return workflowDispatchEvent
}

// getPRFiles returns the list of files updated as part of a PR
func (h *PRCommentHandler) getPRFiles(ctx context.Context, client *github.Client, owner, repo string, prNumber int, logger zerolog.Logger) ([]*github.CommitFile, error) {
	var files []*github.CommitFile
	opt := &github.ListOptions{PerPage: 500}
	for {
		newFiles, response, err := client.PullRequests.ListFiles(ctx, owner, repo, prNumber, opt)
		if err != nil {
			logger.Error().Err(err).Msgf("Failed to retrieve list of files from PR")
			return nil, err
		}
		files = append(files, newFiles...)
		if response.NextPage == 0 {
			break
		}
		opt.Page = response.NextPage
	}
	return files, nil
}

func (h *PRCommentHandler) shouldSkipWorkflow(ctx context.Context, client *github.Client, owner, repo, workflow, SHA string, logger zerolog.Logger) bool {
	runListOpts := &github.ListWorkflowRunsOptions{HeadSHA: SHA, ListOptions: github.ListOptions{PerPage: 1}}
	runs, _, err := client.Actions.ListWorkflowRunsByFileName(ctx, owner, repo, workflow, runListOpts)
	if err != nil {
		logger.Err(err).Msgf("Failed to retrieve list of workflow %s runs for sha=%s", workflow, SHA)
		return false
	}

	// Decide if any available workflow needs to be re-run (i.e. in case it failed)
	if runs != nil && len(runs.WorkflowRuns) > 0 {
		lastRun := runs.WorkflowRuns[0]
		logger.Debug().Msgf("shouldSkipWorkflow? %s/%s:%s, workflow: %s, status: %s, conclusion: %s", owner, repo, SHA, workflow, lastRun.GetStatus(), lastRun.GetConclusion())
		if lastRun.GetStatus() == "completed" {
			conc := lastRun.GetConclusion()
			if conc == "success" || conc == "skipped" {
				logger.Debug().Msgf("Skipping, workflow %s run successfully with the conclusion %s, and there are no changes since the last run", workflow, conc)
				return true
			}
			if conc == "failure" {
				return false
				// BUG(auriaave): https://github.com/cilium/ariane/issues/45
				// var wg sync.WaitGroup
				// h.rerunFailedJobs(ctx, client, owner, repo, workflow, lastRun.GetID(), &wg, logger)
				// return true
			}
		}
	} else {
		logger.Debug().Msgf("cannot skip workflow %s on %s/%s:%s. 'runs' value is nil? %v. Otherwise, no checks run for this workflow", workflow, owner, repo, SHA, runs == nil)
	}
	// Other conclusions will not be skipped
	return false
}

func (h *PRCommentHandler) rerunFailedJobs(ctx context.Context, client *github.Client, owner, repo, workflow string, runID int64, wg *sync.WaitGroup, logger zerolog.Logger) {
	jobListOpts := &github.ListWorkflowJobsOptions{ListOptions: github.ListOptions{PerPage: 200}}
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), h.RunDelay+time.Second*5)
		defer cancel()

		jobs, _, err := client.Actions.ListWorkflowJobs(ctx, owner, repo, runID, jobListOpts)
		if err != nil {
			logger.Err(err).Msgf("Failed to list workflow %s jobs run_id %d", workflow, runID)
			return
		}

		var jobID int64
		// Find the commit-status-start job
		for _, job := range jobs.Jobs {
			if job.GetName() == "Commit Status Start" {
				jobID = job.GetID()
				break
			}
		}
		if jobID != 0 {
			logger.Debug().Msgf("re-running commit-status-start job %d", jobID)
			if _, err := client.Actions.RerunJobByID(ctx, owner, repo, jobID); err != nil {
				logger.Error().Err(err).Msgf("Failed to re-run commit-status-start job_id %d", jobID)
				return
			}
			time.Sleep(h.RunDelay)
		}

		logger.Debug().Msgf("re-running failed workflow %s run_id %d", workflow, runID)
		if _, err := client.Actions.RerunFailedJobsByID(ctx, owner, repo, runID); err != nil {
			logger.Error().Err(err).Msgf("Failed to re-run workflow %s job_id %d", workflow, runID)
		}
	}()
}

func (h *PRCommentHandler) shouldRunWorkflow(ctx context.Context, config *config.ArianeConfig, workflow string, files []*github.CommitFile) bool {
	if _, ok := config.Workflows[workflow]; ok {
		return config.ShouldRunWorkflow(ctx, workflow, files)
	}
	// Runs this if the "workflows" section in ariane-config.yaml
	// does not contain the worfklow (e.g. foo.yaml)
	return config.ShouldRunOnlyWorkflows(ctx, workflow, files)
}

func (h *PRCommentHandler) triggerWorkflow(ctx context.Context, client *github.Client, owner, repo, workflow string, event github.CreateWorkflowDispatchEventRequest, logger zerolog.Logger) error {
	if _, err := client.Actions.CreateWorkflowDispatchEventByFileName(ctx, owner, repo, workflow, event); err != nil {
		logger.Error().Err(err).Msg("Failed to create workflow dispatch event")
		return err
	}
	return nil
}

func (h *PRCommentHandler) markWorkflowAsSkipped(ctx context.Context, client *github.Client, owner, repo, workflow, SHA string, logger zerolog.Logger) error {
	githubWorkflow, _, err := client.Actions.GetWorkflowByFileName(ctx, owner, repo, workflow)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to retrieve workflow")
		return err
	}

	checkRunOptions := github.CreateCheckRunOptions{
		Name:       githubWorkflow.GetName(),
		HeadSHA:    SHA,
		Status:     github.String("completed"),
		Conclusion: github.String("skipped"),
	}
	if _, _, err := client.Checks.CreateCheckRun(ctx, owner, repo, checkRunOptions); err != nil {
		logger.Error().Err(err).Msg("Failed to set check run")
		return err
	}
	return nil
}

func (h *PRCommentHandler) reactToComment(ctx context.Context, client *github.Client, owner, repo string, commentID int64, logger zerolog.Logger) error {
	if _, _, err := client.Reactions.CreateIssueCommentReaction(ctx, owner, repo, commentID, "rocket"); err != nil {
		logger.Error().Err(err).Msg("Failed to react to comment")
		return err
	}
	return nil
}
