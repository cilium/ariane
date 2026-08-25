// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cilium/ariane/internal/config"
	"github.com/cilium/ariane/internal/log"
	"github.com/google/go-github/v88/github"
	"github.com/palantir/go-githubapp/githubapp"
	"github.com/rs/zerolog"
)

const defaultRunTrigger = "/default"

type PullRequestHandler struct {
	githubapp.ClientCreator
	RunDelay         time.Duration
	MaxRetryAttempts int
	// AppBotLogin is Ariane's own bot login, used to recognize the markers it left on
	// deferred commands.
	AppBotLogin string
}

func (*PullRequestHandler) Handles() []string {
	return []string{"pull_request"}
}

// clearPendingTriggerMarkers removes the marker from every command on the pull request
// that is still waiting for its dependencies, so that it is not dispatched against code
// it was not requested for. Only comments that are a command on their own can have been
// deferred, which is what CheckForTrigger tests, and only commands within commentSince
// are reachable by the dispatcher in the first place.
func clearPendingTriggerMarkers(ctx context.Context, client *github.Client, commenter *GithubCommenter, arianeConfig *config.ArianeConfig, owner, repo string, prNumber int, appLogin string, logger zerolog.Logger) error {
	comments, err := getComments(ctx, client, owner, repo, prNumber, logger, time.Now().Add(commentSince), commentLookbackLimit)
	if err != nil {
		return err
	}

	for _, comment := range comments {
		if submatch, _, _ := arianeConfig.CheckForTrigger(ctx, comment.GetBody()); submatch == nil {
			continue
		}

		// The listing reports how many thumbs up each comment carries. When it says
		// there is none, no marker can be there and the lookup that would say so is not
		// worth a request. An absent summary proves nothing, so the lookup still decides.
		if reactions := comment.GetReactions(); reactions != nil && reactions.GetPlusOne() == 0 {
			continue
		}

		reactionID, err := commenter.findReaction(ctx, comment.GetID(), pendingTriggerReaction, appLogin)
		if err != nil {
			logger.Error().Err(err).Msgf("Failed to look up the pending marker on comment %d", comment.GetID())
			continue
		}
		if reactionID == 0 {
			continue
		}

		if err := commenter.removeReaction(ctx, comment.GetID(), reactionID); err != nil {
			logger.Error().Err(err).Msgf("Failed to remove the pending marker from comment %d", comment.GetID())
			continue
		}
		logger.Info().Msgf("Command %q on PR #%d is no longer pending, new commits were pushed", comment.GetBody(), prNumber)
	}

	return nil
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

	botUser := false
	author := ""
	if pr.GetUser().GetLogin() != "" {
		author = pr.GetUser().GetLogin()
	}

	// only handle non-bot comments
	if strings.HasSuffix(author, "[bot]") {
		if !strings.HasPrefix(author, repositoryOwner) {
			comment := fmt.Sprintf("Issue comment was created by an unsupported bot: %s", author)
			logger.Debug().Msg(comment)
			_ = commenter.commentOnPullRequest(ctx, prNumber, comment)
			return fmt.Errorf("pull request author does not contain bot user")
		}
		botUser = true
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

	// New commits invalidate commands that are still awaiting their dependencies: they
	// were requested against the previous head, and their dependencies were checked
	// against it. This is done regardless of who pushed, and a failure must not prevent
	// the default testsuite from running.
	if event.GetAction() == "synchronize" {
		if clearErr := clearPendingTriggerMarkers(ctx, client, commenter, arianeConfig, repositoryOwner, repositoryName, prNumber, p.AppBotLogin, logger); clearErr != nil {
			logger.Error().Err(clearErr).Msgf("Failed to invalidate pending commands on PR #%d", prNumber)
		}
	}

	// only handle comments coming from an allowed organization, if specified
	if !botUser && !isAllowedTeamMember(ctx, client, arianeConfig, repositoryOwner, author, logger) {
		if arianeConfig.GetVerbose() {
			comment := fmt.Sprintf("The default testsuite was requested, but %s cannot trigger the tests. When the reviewers get a chance to inspect this PR, they should review the content of this PR and then trigger the testsuite on your behalf.", author)
			_ = commenter.commentOnPullRequest(ctx, prNumber, comment)
		}
		if err := commenter.reactToPR(ctx, prNumber, "eyes"); err != nil {
			return err
		}
		return fmt.Errorf("author is not an allowed team member")
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
