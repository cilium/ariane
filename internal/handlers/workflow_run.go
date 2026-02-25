// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cilium/ariane/internal/config"
	"github.com/cilium/ariane/internal/log"
	"github.com/google/go-github/v83/github"
	"github.com/palantir/go-githubapp/githubapp"
	"github.com/rs/zerolog"
	"go.uber.org/multierr"
)

type WorkflowRunHandler struct {
	githubapp.ClientCreator
}

func (*WorkflowRunHandler) Handles() []string {
	return []string{"workflow_run"}
}

func (w *WorkflowRunHandler) Handle(ctx context.Context, eventType, deliveryID string, payload []byte) error {
	var event github.WorkflowRunEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return fmt.Errorf("failed to parse workflow_run event payload: %w", err)
	}

	// Only handle completed events
	if action := event.GetAction(); action != "completed" {
		return nil
	}

	installationID := githubapp.GetInstallationIDFromEvent(&event)
	repository := event.GetRepo()
	ctx, logger := githubapp.PrepareRepoContext(ctx, installationID, repository)
	ctx = log.WithLogger(ctx, &logger)

	workflowRun := event.GetWorkflowRun()
	conclusion := workflowRun.GetConclusion()

	// Get the associated pull requests
	pullRequests := workflowRun.PullRequests

	if len(pullRequests) == 0 {
		logger.Debug().Msg("No pull requests associated with this workflow run")
		return nil
	}

	client, err := w.NewInstallationClient(installationID)
	if err != nil {
		return err
	}

	repositoryOwner := repository.GetOwner().GetLogin()
	repositoryName := repository.GetName()

	var fullPR *github.PullRequest

	var arianeConfig *config.ArianeConfig = nil

	// Check if PR creator matches required pattern (starts with repo owner and ends with [bot])
	// If not, check if they are an allowed team member in the config
	// We are getting pull request details in order to get the creator's login, which is not included in the workflow run payload.
	for _, pr := range pullRequests {
		prNumber := pr.GetNumber()
		fullPR, _, err = client.PullRequests.Get(ctx, repositoryOwner, repositoryName, prNumber)
		if err != nil {
			logger.Error().Err(err).Msgf("Failed to get PR #%d details", prNumber)
			continue
		}

		if arianeConfig == nil {
			// Retrieve Ariane configuration from repository based on first PR
			contextRef, _, _ := determineContextRef(fullPR, repositoryOwner, repositoryName, logger)

			// retrieve Ariane configuration (triggers, etc.) from repository based on chosen context
			arianeConfig, err = configGetArianeConfigFromRepository(client, ctx, repositoryOwner, repositoryName, contextRef)
			if err != nil {
				logger.Debug().Err(err).Msg("Failed to retrieve Ariane config")
				return nil
			}
		}

		prCreator := fullPR.GetUser().GetLogin()
		if !strings.HasPrefix(prCreator, repositoryOwner) || !strings.HasSuffix(prCreator, "[bot]") {
			logger.Debug().Msgf("PR #%d creator '%s' does not match required pattern (prefix: '%s', suffix: '[bot]'), checking config", prNumber, prCreator, repositoryOwner)

			if !isAllowedTeamMember(ctx, client, arianeConfig, repositoryOwner, prCreator, logger) {
				logger.Debug().Msgf("PR #%d creator '%s' is not an allowed team member, skipping", prNumber, prCreator)
				fullPR = nil
				continue
			}
		}
	}

	if fullPR == nil {
		logger.Info().Msg("No pull requests with allowed creators associated with this workflow run")
		return nil
	}

	// Handle based on conclusion
	switch conclusion {
	case "success":
		return w.handleSuccessfulRun(ctx, client, &event, workflowRun, fullPR, repositoryOwner, repositoryName, arianeConfig, logger)
	case "failure":
		return w.handleFailedRun(ctx, client, &event, workflowRun, repositoryOwner, repositoryName, arianeConfig, logger)
	default:
		logger.Debug().Msgf("Workflow run conclusion is '%s', not handling", conclusion)
		return nil
	}
}

// handleSuccessfulRun processes successful workflow runs for staged CI/CD and dependent triggers
func (w *WorkflowRunHandler) handleSuccessfulRun(
	ctx context.Context,
	client *github.Client,
	event *github.WorkflowRunEvent,
	workflowRun *github.WorkflowRun,
	pullRequest *github.PullRequest,
	repositoryOwner, repositoryName string,
	arianeConfig *config.ArianeConfig,
	logger zerolog.Logger,
) error {
	prNumber := pullRequest.GetNumber()

	processor := WorkflowProcessor{
		client:       client,
		owner:        repositoryOwner,
		repo:         repositoryName,
		arianeConfig: arianeConfig,
		logger:       logger,
	}

	return multierr.Combine(
		processor.processStages(ctx, pullRequest, prNumber, event, workflowRun),
		processor.processDependantWorkflows(ctx, pullRequest, prNumber, workflowRun),
	)
}

// handleFailedRun processes failed workflow runs and reruns failed jobs
func (w *WorkflowRunHandler) handleFailedRun(
	ctx context.Context,
	client *github.Client,
	event *github.WorkflowRunEvent,
	workflowRun *github.WorkflowRun,
	repositoryOwner, repositoryName string,
	arianeConfig *config.ArianeConfig,
	logger zerolog.Logger,
) error {
	runID := workflowRun.GetID()
	workflowName := event.GetWorkflow().GetName()
	workflowPath := event.GetWorkflow().GetPath()
	pullRequests := workflowRun.PullRequests

	logger.Info().Msgf("Workflow '%s' (run ID: %d) failed, checking if rerun is needed", workflowName, runID)

	// Get the first PR to check configuration
	if len(pullRequests) == 0 {
		logger.Debug().Msg("No pull requests associated with this workflow run")
		return nil
	}

	if arianeConfig.RerunConfig == nil {
		logger.Debug().Msgf("No rerun configuration found, skipping workflow '%s' rerun", workflowPath)
		return nil
	} else {
		// Check if this workflow is in the exclude list
		for _, excludedWorkflow := range arianeConfig.RerunConfig.ExcludeWorkflows {
			if strings.Contains(workflowPath, excludedWorkflow) {
				logger.Debug().Msgf("Workflow '%s' is in the exclude list, skipping rerun", workflowPath)
				return nil
			}
		}

		// Check if this workflow is in the allowed list
		// If Workflows is empty, assume all workflows are allowed
		if len(arianeConfig.RerunConfig.Workflows) > 0 {
			workflowAllowed := false
			for _, allowedWorkflow := range arianeConfig.RerunConfig.Workflows {
				if strings.Contains(workflowPath, allowedWorkflow) {
					workflowAllowed = true
					break
				}
			}

			if !workflowAllowed {
				logger.Debug().Msgf("Workflow '%s' is not in the rerun allowed list, skipping", workflowPath)
				return nil
			}

			logger.Debug().Msgf("Workflow '%s' is in the rerun allowed list", workflowPath)
		} else {
			logger.Debug().Msg("No workflow restrictions configured, allowing rerun for all workflows")
		}
	}

	maxRetries := 0
	if arianeConfig != nil && arianeConfig.RerunConfig != nil {
		maxRetries = arianeConfig.RerunConfig.MaxRetries
	}

	// Check if we've exceeded max retries
	run, _, err := client.Actions.GetWorkflowRunByID(ctx, repositoryOwner, repositoryName, runID)
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to get workflow run %d", runID)
		return err
	}

	runAttempt := run.GetRunAttempt()
	logger.Debug().Msgf("Workflow run %d is at attempt %d (max retries: %d)", runID, runAttempt, maxRetries)

	if runAttempt > maxRetries {
		logger.Info().Msgf("Workflow run %d has reached max retries (%d/%d), not rerunning", runID, runAttempt-1, maxRetries)
		return nil
	}

	logger.Info().Msgf("Proceeding with rerun (attempt %d/%d)", runAttempt, maxRetries)

	// Check if there are any failed jobs that can be rerun
	if err := rerunFailedJobs(ctx, client, repositoryOwner, repositoryName, runID, workflowName, logger); err != nil {
		logger.Error().Err(err).Msgf("Failed to rerun failed jobs for workflow '%s'", workflowName)
		return err
	}

	logger.Info().Msgf("Successfully triggered rerun for workflow '%s'", workflowName)
	return nil
}
