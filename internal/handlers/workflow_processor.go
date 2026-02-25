// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/ariane/internal/config"
	"github.com/google/go-github/v83/github"
	"github.com/rs/zerolog"
)

type WorkflowProcessor struct {
	client       *github.Client
	arianeConfig *config.ArianeConfig
	owner        string
	repo         string
	logger       zerolog.Logger
	runDelay     time.Duration
}

func (w *WorkflowProcessor) processWorkflow(
	ctx context.Context,
	workflow string,
	files []*github.CommitFile,
	workflowDispatchEvent github.CreateWorkflowDispatchEventRequest,
	sha string,
) *workflowStatus {
	// Check if workflow already completed
	if w.shouldSkipWorkflow(ctx, workflow, sha) {
		if w.arianeConfig.GetReportAllWorkflows() {
			return &workflowStatus{name: workflow, status: workflowStatusAlreadyCompleted}
		}
		return nil
	}

	// Check if workflow should run based on file changes
	if w.shouldRunWorkflow(ctx, workflow, files) {
		if err := w.triggerWorkflow(ctx, workflow, workflowDispatchEvent); err != nil {
			w.logger.Error().Err(err).Msgf("Failed to trigger workflow %s", workflow)
			return &workflowStatus{name: workflow, status: workflowStatusFailed}
		}
		if w.arianeConfig.GetReportAllWorkflows() {
			return &workflowStatus{name: workflow, status: workflowStatusTriggered}
		}
		return nil
	}

	// Workflow should be skipped
	if err := w.markWorkflowAsSkipped(ctx, workflow, sha); err != nil {
		w.logger.Error().Err(err).Msgf("Failed to mark workflow %s as skipped", workflow)
		return &workflowStatus{name: workflow, status: workflowStatusFailedToMarkSkipped}
	}
	if w.arianeConfig.GetReportAllWorkflows() {
		return &workflowStatus{name: workflow, status: workflowStatusSkipped}
	}
	return nil
}

func (w *WorkflowProcessor) shouldSkipWorkflow(ctx context.Context, workflow, SHA string) bool {
	runListOpts := &github.ListWorkflowRunsOptions{HeadSHA: SHA, ListOptions: github.ListOptions{PerPage: 1}}
	runs, _, err := w.client.Actions.ListWorkflowRunsByFileName(ctx, w.owner, w.repo, workflow, runListOpts)
	if err != nil {
		w.logger.Err(err).Msgf("Failed to retrieve list of workflow %s runs for sha=%s", workflow, SHA)
		return false
	}

	// Decide if any available workflow needs to be re-run (i.e. in case it failed)
	if runs != nil && len(runs.WorkflowRuns) > 0 {
		lastRun := runs.WorkflowRuns[0]
		w.logger.Debug().Msgf("shouldSkipWorkflow? %s/%s:%s, workflow: %s, status: %s, conclusion: %s", w.owner, w.repo, SHA, workflow, lastRun.GetStatus(), lastRun.GetConclusion())
		if lastRun.GetStatus() == "completed" {
			conc := lastRun.GetConclusion()
			if conc == "success" || conc == "skipped" {
				w.logger.Debug().Msgf("Skipping, workflow %s run successfully with the conclusion %s, and there are no changes since the last run", workflow, conc)
				return true
			}
			if conc == "failure" {
				var wg sync.WaitGroup
				w.rerunFailedJobs(ctx, workflow, lastRun.GetID(), &wg)
				return true
			}
		}
	} else {
		w.logger.Debug().Msgf("cannot skip workflow %s on %s/%s:%s. 'runs' value is nil? %v. Otherwise, no checks run for this workflow", workflow, w.owner, w.repo, SHA, runs == nil)
	}
	// Other conclusions will not be skipped
	return false
}

func (w *WorkflowProcessor) shouldRunWorkflow(ctx context.Context, workflow string, files []*github.CommitFile) bool {
	if _, ok := w.arianeConfig.Workflows[workflow]; ok {
		return w.arianeConfig.ShouldRunWorkflow(ctx, workflow, files)
	}
	// Runs this if the "workflows" section in ariane-config.yaml
	// does not contain the worfklow (e.g. foo.yaml)
	return w.arianeConfig.ShouldRunOnlyWorkflows(ctx, workflow, files)
}

func (w *WorkflowProcessor) triggerWorkflow(ctx context.Context, workflow string, event github.CreateWorkflowDispatchEventRequest) error {
	if _, err := w.client.Actions.CreateWorkflowDispatchEventByFileName(ctx, w.owner, w.repo, workflow, event); err != nil {
		w.logger.Error().Err(err).Msg("Failed to create workflow dispatch event")
		return err
	}
	return nil
}

func (w *WorkflowProcessor) rerunFailedJobs(ctx context.Context, workflow string, runID int64, wg *sync.WaitGroup) {
	jobListOpts := &github.ListWorkflowJobsOptions{ListOptions: github.ListOptions{PerPage: 200}}
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(ctx, w.runDelay+time.Second*5)
		defer cancel()

		jobs, _, err := w.client.Actions.ListWorkflowJobs(ctx, w.owner, w.repo, runID, jobListOpts)
		if err != nil {
			w.logger.Err(err).Msgf("Failed to list workflow %s jobs run_id %d", workflow, runID)
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
			w.logger.Debug().Msgf("re-running commit-status-start job %d", jobID)
			if _, err := w.client.Actions.RerunJobByID(ctx, w.owner, w.repo, jobID); err != nil {
				w.logger.Error().Err(err).Msgf("Failed to re-run commit-status-start job_id %d", jobID)
				return
			}
			time.Sleep(w.runDelay)
		}

		w.logger.Debug().Msgf("re-running failed workflow %s run_id %d", workflow, runID)
		if _, err := w.client.Actions.RerunFailedJobsByID(ctx, w.owner, w.repo, runID); err != nil {
			w.logger.Error().Err(err).Msgf("Failed to re-run workflow %s job_id %d", workflow, runID)
		}
	}()
}

func (w *WorkflowProcessor) markWorkflowAsSkipped(ctx context.Context, workflow, SHA string) error {
	githubWorkflow, _, err := w.client.Actions.GetWorkflowByFileName(ctx, w.owner, w.repo, workflow)
	if err != nil {
		w.logger.Error().Err(err).Msg("Failed to retrieve workflow")
		return err
	}

	checkRunOptions := github.CreateCheckRunOptions{
		Name:       githubWorkflow.GetName(),
		HeadSHA:    SHA,
		Status:     github.Ptr("completed"),
		Conclusion: github.Ptr("skipped"),
	}
	if _, _, err := w.client.Checks.CreateCheckRun(ctx, w.owner, w.repo, checkRunOptions); err != nil {
		w.logger.Error().Err(err).Msg("Failed to set check run")
		return err
	}
	return nil
}

// Creates a reference for a workflow, in order to run it via workflow_dispatch
func (w *WorkflowProcessor) createWorkflowDispatchEvent(prNumber int, contextRef, headSHA, baseSHA string, submatch []string) github.CreateWorkflowDispatchEventRequest {
	workflowDispatchEvent := github.CreateWorkflowDispatchEventRequest{
		Ref: contextRef,
		// These are parameters (inputs) on workflow_dispatch
		Inputs: map[string]interface{}{
			"PR-number":   strconv.Itoa(prNumber),
			"context-ref": contextRef,
			"SHA":         headSHA,
			"base-SHA":    baseSHA,
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
func (w *WorkflowProcessor) getPRFiles(ctx context.Context, prNumber int) ([]*github.CommitFile, error) {
	var files []*github.CommitFile
	opt := &github.ListOptions{PerPage: 500}
	for {
		newFiles, response, err := w.client.PullRequests.ListFiles(ctx, w.owner, w.repo, prNumber, opt)
		if err != nil {
			w.logger.Error().Err(err).Msgf("Failed to retrieve list of files from PR")
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

func (w *WorkflowProcessor) processWorkflowsForTrigger(ctx context.Context, submatch []string, prNumber int, contextRef, headSHA, baseSHA string, workflowsToTrigger, dependsOn []string, commenter *GithubCommenter) error {
	w.logger.Debug().Msgf("Found trigger phrase: %q", submatch)

	// Check if this trigger has dependencies
	if len(dependsOn) > 0 {
		w.logger.Debug().Msgf("Trigger depends on: %q", dependsOn)
		for _, dep := range dependsOn {
			canProceed, inProgress, err := w.checkTriggerDependency(ctx, dep, headSHA)
			if err != nil {
				return fmt.Errorf("failed to check trigger dependency %q: %v", dep, err)
			}
			if !canProceed {
				var comment string
				if inProgress {
					comment = fmt.Sprintf("Skipping trigger: dependency %q is still in progress", dep)
				} else {
					comment = fmt.Sprintf("Skipping trigger: dependency %q has not completed successfully", dep)
				}
				w.logger.Info().Msg(comment)

				return errors.New(comment)
			}
			w.logger.Debug().Msgf("Dependency %q check passed", dep)
		}
	}

	workflowDispatchEvent := w.createWorkflowDispatchEvent(prNumber, contextRef, headSHA, baseSHA, submatch)

	files, err := w.getPRFiles(ctx, prNumber)
	if err != nil {
		comment := fmt.Sprintf("Failed to retrieve pull request files: %v", err)
		if w.arianeConfig.GetVerbose() {
			_ = commenter.commentOnPullRequest(ctx, prNumber, comment)
		}
		return err
	}

	var workflowStatuses []workflowStatus

	for _, workflow := range workflowsToTrigger {
		status := w.processWorkflow(ctx, workflow, files, workflowDispatchEvent, headSHA)
		if status != nil {
			workflowStatuses = append(workflowStatuses, *status)
		}
	}

	// Build summary comment with workflow status table
	if w.arianeConfig.GetVerbose() && w.arianeConfig.GetWorkflowsReport() && len(workflowStatuses) > 0 {
		comment := buildWorkflowStatusTable(workflowStatuses)
		_ = commenter.commentOnPullRequest(ctx, prNumber, comment)
	}
	return nil
}

// checkTriggerDependency checks if all workflows from the dependency trigger have completed successfully or been skipped
func (w *WorkflowProcessor) checkTriggerDependency(ctx context.Context, dependsOnTrigger, sha string) (canRun bool, inProgress bool, err error) {
	// Get the trigger configuration for the dependency
	dependencyTrigger, exists := w.arianeConfig.Triggers[dependsOnTrigger]
	if !exists {
		return false, false, fmt.Errorf("dependency trigger %q not found in configuration", dependsOnTrigger)
	}

	// Check all workflows from the dependency trigger
	for _, workflow := range dependencyTrigger.Workflows {
		// Get workflow runs for this SHA
		runListOpts := &github.ListWorkflowRunsOptions{
			HeadSHA:     sha,
			ListOptions: github.ListOptions{PerPage: 10},
		}
		runs, _, err := w.client.Actions.ListWorkflowRunsByFileName(ctx, w.owner, w.repo, workflow, runListOpts)
		if err != nil {
			return false, false, fmt.Errorf("failed to list workflow runs for %s: %w", workflow, err)
		}

		if runs.GetTotalCount() == 0 {
			// No runs found for this workflow - dependency not satisfied
			w.logger.Debug().Msgf("No runs found for dependency workflow %s", workflow)
			return false, false, nil
		}

		// Check if the latest run has completed successfully or been skipped
		latestRun := runs.WorkflowRuns[0]
		status := latestRun.GetStatus()
		conclusion := latestRun.GetConclusion()

		w.logger.Debug().Msgf("Dependency workflow %s: status=%s, conclusion=%s", workflow, status, conclusion)

		// Conclusion must be success or skipped
		if conclusion != "success" && conclusion != "skipped" {
			inProgress = status == "in_progress"
			if inProgress {
				w.logger.Debug().Msgf("Dependency workflow %s is still in progress (conclusion: %s)", workflow, conclusion)
			} else {
				w.logger.Debug().Msgf("Dependency workflow %s did not succeed (conclusion: %s)", workflow, conclusion)
			}
			return false, inProgress, nil
		}
	}

	// All dependency workflows have completed successfully or been skipped
	return true, false, nil
}

const commentSince = -3 * time.Hour
const recentCutoff = -15 * time.Minute
const commentLookbackLimit = 100

// processDependantWorkflows checks if the completed workflow run satisfies any trigger dependencies
// and posts the corresponding command on the PR if all dependencies are met and the command was posted previously within the last commentSince.
// To avoid spam, we use recentCutoff to not post the command if it was already posted recently (e.g. within the last 15 minutes)
func (w *WorkflowProcessor) processDependantWorkflows(ctx context.Context, pullRequest *github.PullRequest, prNumber int, workflowRun *github.WorkflowRun) error {
triggers:
	for triggerPhrase, trigger := range w.arianeConfig.Triggers {
		for _, dependencyTriggerPhrase := range trigger.DependsOn {
			dependencyTrigger, ok := w.arianeConfig.Triggers[dependencyTriggerPhrase]
			if !ok {
				return errors.New("dependency trigger " + dependencyTriggerPhrase + " not found in Ariane trigger config")
			}

			for _, workflow := range dependencyTrigger.Workflows {
				if filepath.Base(workflowRun.GetPath()) == workflow {
					// successful workflow run is a part of dependency for a trigger, check if all dependencies are met and if so, post the command on the PR if it was posted previously (but not very recently)
					dependenciesSatisfied, _, err := w.checkTriggerDependency(ctx, dependencyTriggerPhrase, pullRequest.GetHead().GetSHA())
					if err != nil {
						w.logger.Error().Err(err).Msgf("Failed to check dependencies for trigger '%s'", triggerPhrase)
					}
					if dependenciesSatisfied {
						since := time.Now().Add(commentSince) // Check comments from the last 3 hours
						recent := time.Now().Add(recentCutoff)

						comments, err := getComments(ctx, w.client, w.owner, w.repo, prNumber, w.logger, since, commentLookbackLimit)
						if err != nil {
							w.logger.Error().Err(err).Msgf("Failed to retrieve comments for PR #%d", prNumber)
							continue
						}
						foundTriggerComment := ""
						foundRecentTriggerComment := false
						re, err := regexp.Compile(triggerPhrase)
						if err != nil {
							w.logger.Error().Err(err).Msgf("Failed to compile regex for trigger phrase '%s'", triggerPhrase)
							continue triggers
						}
						for _, comment := range comments {
							if re.MatchString(comment.GetBody()) {
								foundTriggerComment = comment.GetBody()
								if comment.CreatedAt.GetTime().After(recent) {
									foundRecentTriggerComment = true
									break
								}
							}
						}
						if len(foundTriggerComment) > 0 && !foundRecentTriggerComment { // do not post comment if it was posted within recentCutoff time
							w.logger.Info().Msgf("All dependencies for trigger '%s' are satisfied, posting command on PR #%d", triggerPhrase, prNumber)
							if err := commentOnPullRequest(ctx, w.client, w.owner, w.repo, prNumber, foundTriggerComment, w.logger); err != nil {
								w.logger.Error().Err(err).Msgf("Failed to post command on PR #%d", prNumber)
							}
							continue triggers
						}
					}
				}
			}
		}
	}

	return nil
}

func (w *WorkflowProcessor) processStages(ctx context.Context, pullRequest *github.PullRequest, prNumber int, event *github.WorkflowRunEvent, workflowRun *github.WorkflowRun) error {
	// Check if stages are configured
	if w.arianeConfig.StagesConfig == nil {
		w.logger.Debug().Msg("No stages configured")
		return nil
	}

	requiredLabel := w.arianeConfig.StagesConfig.Label
	if requiredLabel == "" {
		w.logger.Debug().Msg("No label for stages configured")
		return nil
	}

	// Check if the PR has the required label
	hasLabel, err := prHasLabel(ctx, w.client, pullRequest, requiredLabel, w.logger)
	if err != nil {
		w.logger.Error().Err(err).Msgf("Failed to check labels for PR #%d", prNumber)
		return err
	}

	if !hasLabel {
		w.logger.Debug().Msgf("PR #%d does not have %s label, skipping", prNumber, requiredLabel)
		return nil
	}

	w.logger.Info().Msgf("PR #%d has %s label, processing workflow run", prNumber, requiredLabel)

	// Get the workflow filename
	workflowPath := event.GetWorkflow().GetPath()
	workflowFileName := filepath.Base(workflowPath)

	// Find matching stage configuration
	matchedStages := make([]config.Stage, 0)
	for _, stage := range w.arianeConfig.StagesConfig.Stages {
		for _, workflow := range stage.Workflows {
			if workflow == workflowFileName {
				matchedStages = append(matchedStages, stage)
				w.logger.Info().Msgf("Workflow %s completed, matched stage with command: %s", workflowFileName, stage.Command)
			}
		}
	}

	if len(matchedStages) == 0 {
		w.logger.Debug().Msgf("Workflow %s has no configured handler", workflowFileName)
		return nil
	}

	// Check that all workflows in the stage have completed successfully
	for _, stage := range matchedStages {
		for _, workflow := range stage.Workflows {
			workflowRuns, err := getWorkflowRuns(ctx, w.client, w.owner, w.repo, workflow, workflowRun.GetHeadSHA(), w.logger)
			if err != nil {
				w.logger.Error().Err(err).Msgf("Failed to get workflow runs for workflow %s", workflow)
				return err
			}
			for _, run := range workflowRuns.WorkflowRuns {
				if run.GetConclusion() != "success" {
					w.logger.Debug().Msgf("Workflow %s has not completed successfully yet", workflow)
					return nil
				}
			}
		}
		prNumber := pullRequest.GetNumber()
		w.logger.Info().Msgf("Posting command '%s' on PR #%d", stage.Command, prNumber)

		if err := commentOnPullRequest(ctx, w.client, w.owner, w.repo, prNumber, stage.Command, w.logger); err != nil {
			w.logger.Error().Err(err).Msgf("Failed to post command on PR #%d", prNumber)
			// Continue with other PRs even if one fails
			continue
		}
	}

	return nil
}
