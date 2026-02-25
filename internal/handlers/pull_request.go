// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cilium/ariane/internal/log"
	"github.com/google/go-github/v83/github"
	"github.com/palantir/go-githubapp/githubapp"
	"github.com/rs/zerolog"
)

const defaultRunTrigger = "/default"

type PullRequestHandler struct {
	githubapp.ClientCreator
	RunDelay         time.Duration
	MaxRetryAttempts int
}

func (*PullRequestHandler) Handles() []string {
	return []string{"pull_request"}
}

func (p *PullRequestHandler) Handle(ctx context.Context, eventType, deliveryID string, payload []byte) error {
	var event github.PullRequestEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return fmt.Errorf("failed to parse pull_request event payload: %w", err)
	}

	installationID := githubapp.GetInstallationIDFromEvent(&event)
	repository := event.GetRepo()
	prNumber := event.GetPullRequest().GetNumber()
	ctx, logger := githubapp.PreparePRContext(ctx, installationID, repository, prNumber)
	ctx = log.WithLogger(ctx, &logger)
	allowedActions := []string{"opened", "reopened", "synchronize"}
	isAllowedAction := false
	// only handle allowed pull requests actions
	for _, action := range allowedActions {
		if event.GetAction() == action {
			isAllowedAction = true
			break
		}
	}
	if !isAllowedAction {
		zerolog.Ctx(ctx).Debug().Msgf("Pull request action is not any of %s; skipping", allowedActions)
		return nil
	}

	client, err := p.NewInstallationClient(installationID)

	if err != nil {
		return err
	}

	repositoryOwner := repository.GetOwner().GetLogin()
	repositoryName := repository.GetName()

	commenter := NewGithubCommenter(client, repositoryOwner, repositoryName, logger)

	// Get PR metadata and validate PR author permissions
	pr, err := getPullRequest(ctx, client, repositoryOwner, repositoryName, prNumber, logger, p.MaxRetryAttempts)
	if err != nil {
		comment := fmt.Sprintf("Failed to retrieve pull request: %v", err)
		logger.Error().Err(err).Msg(comment)
		_ = commenter.commentOnPullRequest(ctx, prNumber, comment)
		return err
	}

	contextRef, headSHA, baseSHA := determineContextRef(pr, repositoryOwner, repositoryName, logger)
	logger.Debug().Str("context_ref", contextRef).Str("head_sha", headSHA).Str("base_sha", baseSHA).Msg("Determined context for configuration retrieval")

	// retrieve Ariane configuration (triggers, etc.) from repository based on chosen context
	arianeConfig, err := configGetArianeConfigFromRepository(client, ctx, repositoryOwner, repositoryName, contextRef)
	if err != nil {
		comment := "Failed to retrieve config file"
		logger.Error().Err(err).Msg(comment)
		_ = commenter.commentOnPullRequest(ctx, prNumber, comment)
		return err
	}

	// only handle comments matching a registered trigger, and retrieve associated list of workflows to trigger
	submatch, workflowsToTrigger, dependsOn := arianeConfig.CheckForTrigger(ctx, defaultRunTrigger)
	logger.Debug().Int("len", len(workflowsToTrigger)).Msg("")
	// the command on commentBody (e.g. /test-this) does not match any "triggers"
	if submatch == nil {
		logger.Debug().Msg("No matches for /default trigger")
		return nil
	}

	if err := commenter.reactToPR(ctx, prNumber, "eyes"); err != nil {
		return err
	}

	processor := WorkflowProcessor{
		client:       client,
		owner:        repositoryOwner,
		repo:         repositoryName,
		arianeConfig: arianeConfig,
		logger:       logger,
		runDelay:     p.RunDelay,
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

	if err := commenter.reactToPR(ctx, prNumber, "rocket"); err != nil {
		return err
	}

	return nil
}
