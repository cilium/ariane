// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package handlers

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/go-github/v75/github"
	"github.com/cilium/ariane/internal/log"
	"github.com/palantir/go-githubapp/githubapp"
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

	branchRef := event.GetMergeGroup().GetBaseRef()
	branchPro, _, err := client.Repositories.GetBranchProtection(ctx, repositoryOwner, repositoryName, branchRef)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to retrieve branch protection rules")
		return err
	}

	headSHA := event.GetMergeGroup().GetHeadSHA()
	for _, ch := range branchPro.GetRequiredStatusChecks().GetChecks() {
		// required checks' appID is 0 for any source configuration
		// if appID is not equal to 0 this means check is handled by some other app or by GitHub
		// we skipp these checks
		if ch.GetAppID() != 0 {
			logger.Debug().Str("Status Check", ch.Context).Msg("Not managed by Ariane")
			continue
		}

		// setting the check status as completed and conclusion as success, without actually running it
		logger.Debug().Str("Status Check", ch.Context).Msg("Setting status to completed, conclusion to success")
		checkRunOptions := github.CreateCheckRunOptions{
			Name:       ch.Context,
			HeadSHA:    headSHA,
			Status:     github.String("completed"),
			Conclusion: github.String("success"),
		}
		if _, _, err := client.Checks.CreateCheckRun(ctx, repositoryOwner, repositoryName, checkRunOptions); err != nil {
			logger.Error().Err(err).Msgf("Failed to set check run, %s", ch.Context)
		}
	}

	return nil
}
