// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/go-github/v83/github"
	"github.com/palantir/go-githubapp/githubapp"
	"github.com/rs/zerolog"

	"github.com/cilium/ariane/internal/config"
	"github.com/cilium/ariane/internal/log"
)

var configGetArianeConfigFromRepository = config.GetArianeConfigFromRepository

type PRCommentHandler struct {
	githubapp.ClientCreator
	RunDelay         time.Duration
	MaxRetryAttempts int
}

type workflowStatusType string

const (
	workflowStatusTriggered           workflowStatusType = "triggered"
	workflowStatusSkipped             workflowStatusType = "skipped"
	workflowStatusAlreadyCompleted    workflowStatusType = "already completed"
	workflowStatusFailed              workflowStatusType = "failed"
	workflowStatusFailedToMarkSkipped workflowStatusType = "failed to mark as skipped"
)

type workflowStatus struct {
	name   string
	status workflowStatusType
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

	// skip all comments that do not start with / (with optional leading whitespace)
	if !strings.HasPrefix(strings.TrimSpace(commentBody), "/") {
		return nil
	}

	commenter := NewGithubCommenter(client, repositoryOwner, repositoryName, logger)

	// only handle non-bot comments
	if strings.HasSuffix(commentAuthor, "[bot]") {
		if !strings.HasPrefix(commentAuthor, repositoryOwner) {
			comment := fmt.Sprintf("Issue comment was created by an unsupported bot: %s", commentAuthor)
			logger.Debug().Msg(comment)
			_ = commenter.commentOnPullRequest(ctx, prNumber, comment)
			return nil
		}
		botUser = true
	}

	// Get PR metadata and validate PR author permissions
	pr, err := getPullRequest(ctx, client, repositoryOwner, repositoryName, prNumber, logger, h.MaxRetryAttempts)
	if err != nil {
		comment := fmt.Sprintf("Failed to retrieve pull request: %v", err)
		logger.Error().Err(err).Msg(comment)
		_ = commenter.commentOnPullRequest(ctx, prNumber, comment)
		return err
	}

	contextRef, headSHA, baseSHA := determineContextRef(pr, repositoryOwner, repositoryName, logger)

	// retrieve Ariane configuration (triggers, etc.) from repository based on chosen context
	arianeConfig, err := configGetArianeConfigFromRepository(client, ctx, repositoryOwner, repositoryName, contextRef)
	if err != nil {
		comment := "Failed to retrieve config file"
		logger.Error().Err(err).Msg(comment)
		_ = commenter.commentOnPullRequest(ctx, prNumber, comment)
		return err
	}

	// only handle comments coming from an allowed organization, if specified
	if !botUser && !isAllowedTeamMember(ctx, client, arianeConfig, repositoryOwner, commentAuthor, logger) {
		// TODO It would be beneficial to provide feedback indicating that the test run was rejected.
		// Initially considered updating the comment with a "no entry" emoji, but given the limited
		// selection of emojis that can be used, none appeared to be entirely fitting.
		// Maybe alternative feedback mechanisms should be explored to communicate the rejection status clearly.
		if arianeConfig.GetVerbose() {
			comment := fmt.Sprintf("Comment by %s not allowed", commentAuthor)
			_ = commenter.commentOnPullRequest(ctx, prNumber, comment)
		}
		return nil
	}

	// only handle comments matching a registered trigger, and retrieve associated list of workflows to trigger
	submatch, workflowsToTrigger, dependsOn := arianeConfig.CheckForTrigger(ctx, commentBody)
	// the command on commentBody (e.g. /test-this) does not match any "triggers"
	if submatch == nil {
		if arianeConfig.GetVerbose() {
			comment := fmt.Sprintf("Command %s not found", commentBody)
			_ = commenter.commentOnPullRequest(ctx, prNumber, comment)
		}
		return nil
	}

	if err := commenter.reactToComment(ctx, commentID, "eyes"); err != nil {
		return err
	}

	processor := WorkflowProcessor{
		client:       client,
		owner:        repositoryOwner,
		repo:         repositoryName,
		arianeConfig: arianeConfig,
		logger:       logger,
		runDelay:     h.RunDelay,
	}

	err = processor.processWorkflowsForTrigger(ctx, submatch, prNumber, contextRef, headSHA, baseSHA, workflowsToTrigger, dependsOn, commenter)
	if err != nil {
		comment := fmt.Sprintf("Failed to process workflows for trigger: %v", err)
		logger.Error().Err(err).Msg(comment)
		if arianeConfig.GetVerbose() {
			_ = commenter.commentOnPullRequest(ctx, prNumber, comment)
		}
		return err
	}

	if err := commenter.reactToComment(ctx, commentID, "rocket"); err != nil {
		return err
	}

	return nil
}

// getPullRequest returns a PR object to retrieve a pull request metadata
func getPullRequest(ctx context.Context, client *github.Client, owner, repo string, prNumber int, logger zerolog.Logger, maxRetryAttempts int) (*github.PullRequest, error) {
	var pr *github.PullRequest
	var err error

	for attempt := 0; attempt <= maxRetryAttempts; attempt++ {
		pr, _, err = client.PullRequests.Get(ctx, owner, repo, prNumber)
		if err == nil {
			break
		}

		if attempt < maxRetryAttempts {
			backoffDuration := time.Duration(math.Pow(2, float64(attempt-1))) * time.Second
			logger.Warn().Err(err).Msgf("Failed to retrieve pull request on attempt %d, retrying in %v", attempt, backoffDuration)
			time.Sleep(backoffDuration)
			continue
		}

		logger.Error().Err(err).Msgf("Failed to retrieve pull request after %d attempts", attempt)
		return nil, err
	}

	// return pr number if is open
	if pr.GetState() != "open" {
		err = errors.New("pull request is not open")
		logger.Error().Err(err).Msgf("Pull request is not open")
		return nil, err
	}

	return pr, nil
}

func determineContextRef(pr *github.PullRequest, owner, repo string, logger zerolog.Logger) (contextRef, headSHA, baseSHA string) {
	headSHA = pr.GetHead().GetSHA()
	baseSHA = pr.GetBase().GetSHA()
	prOwner := pr.GetHead().GetRepo().GetOwner().GetLogin()
	prRepo := pr.GetHead().GetRepo().GetName()

	// PR comes from a fork
	if prOwner != owner || prRepo != repo {
		contextRef = pr.GetBase().GetRef()
		logger.Debug().Msgf("PR is from a fork, workflows for %s will run in the context of the PR target branch %s", headSHA, contextRef)
	} else {
		contextRef = pr.GetHead().GetRef()
		logger.Debug().Msgf("PR is not from a fork, workflows for %s will run in the context of the PR branch %s", headSHA, contextRef)
	}
	return contextRef, headSHA, baseSHA
}
