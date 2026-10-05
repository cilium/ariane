// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"strings"

	"github.com/cilium/ariane/internal/log"
	"github.com/google/go-github/v92/github"
	"github.com/palantir/go-githubapp/githubapp"
	"github.com/rs/zerolog"
	"go.uber.org/multierr"
)

type MergeGroupHandler struct {
	githubapp.ClientCreator
}

func (*MergeGroupHandler) Handles() []string {
	return []string{"merge_group"}
}

func (m *MergeGroupHandler) Handle(ctx context.Context, eventType, deliveryID string, payload []byte) error {
	var event github.MergeGroupEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return fmt.Errorf("failed to parse merge_group event payload: %w", err)
	}

	if action := event.GetAction(); action != "checks_requested" {
		// we only handle checks requested event
		return nil
	}

	installationID := githubapp.GetInstallationIDFromEvent(&event)
	repository := event.GetRepo()
	ctx, logger := githubapp.PrepareRepoContext(ctx, installationID, repository)
	ctx = log.WithLogger(ctx, &logger)

	client, err := m.NewInstallationClient(installationID)
	if err != nil {
		return err
	}

	repositoryOwner := repository.GetOwner().GetLogin()
	repositoryName := repository.GetName()

	branch := strings.TrimPrefix(event.GetMergeGroup().GetBaseRef(), "refs/heads/")

	classic, classicErr := collectClassicChecks(ctx, client, repositoryOwner, repositoryName, branch, &logger)
	rulesets, rulesetsErr := collectRulesetChecks(ctx, client, repositoryOwner, repositoryName, branch, &logger)
	if err := multierr.Combine(classicErr, rulesetsErr); err != nil {
		return err
	}

	contexts := make(map[string]struct{}, len(classic)+len(rulesets))
	maps.Copy(contexts, classic)
	maps.Copy(contexts, rulesets)

	headSHA := event.GetMergeGroup().GetHeadSHA()
	for checkContext := range contexts {
		// setting the check status as completed and conclusion as success, without actually running it
		logger.Debug().Str("Status Check", checkContext).Msg("Setting status to completed, conclusion to success")
		checkRunOptions := github.CreateCheckRunOptions{
			Name:       checkContext,
			HeadSHA:    headSHA,
			Status:     new("completed"),
			Conclusion: new("success"),
		}
		if _, _, err := client.Checks.CreateCheckRun(ctx, repositoryOwner, repositoryName, checkRunOptions); err != nil {
			logger.Error().Err(err).Msgf("Failed to set check run, %s", checkContext)
		}
	}

	return nil
}

// addAnySourceCheck adds check to contexts unless it is pinned to an app (id != 0).
func addAnySourceCheck(contexts map[string]struct{}, check string, id int64, logger *zerolog.Logger) {
	if id != 0 {
		logger.Debug().Str("Status Check", check).Msg("Not managed by Ariane")
		return
	}
	contexts[check] = struct{}{}
}

func collectClassicChecks(ctx context.Context, client *github.Client, owner, repo, branch string, logger *zerolog.Logger) (map[string]struct{}, error) {
	contexts := make(map[string]struct{})
	protection, resp, err := client.Repositories.GetBranchProtection(ctx, owner, repo, branch)
	if err != nil {
		// an unprotected branch 404s, which just means no checks here
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return contexts, nil
		}
		return nil, fmt.Errorf("classic branch protection: %w", err)
	}

	for _, check := range protection.GetRequiredStatusChecks().GetChecks() {
		addAnySourceCheck(contexts, check.Context, check.GetAppID(), logger)
	}
	return contexts, nil
}

func collectRulesetChecks(ctx context.Context, client *github.Client, owner, repo, branch string, logger *zerolog.Logger) (map[string]struct{}, error) {
	contexts := make(map[string]struct{})
	opts := &github.ListOptions{}
	for {
		branchRules, resp, err := client.Repositories.ListRulesForBranch(ctx, owner, repo, branch, opts)
		if err != nil {
			// the rules endpoint only 404s if the branch or repo is missing
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				return contexts, nil
			}
			return nil, fmt.Errorf("branch rules: %w", err)
		}

		for _, rule := range branchRules.GetRequiredStatusChecks() {
			for _, check := range rule.Parameters.RequiredStatusChecks {
				addAnySourceCheck(contexts, check.Context, check.GetIntegrationID(), logger)
			}
		}

		if resp.NextPage == 0 {
			return contexts, nil
		}
		opts.Page = resp.NextPage
	}
}
