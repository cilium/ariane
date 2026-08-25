// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package handlers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cilium/ariane/internal/config"
	"github.com/google/go-github/v88/github"
	"github.com/palantir/go-githubapp/githubapp"
	"github.com/rs/zerolog"
)

// ResolveAppBotLogin returns the login of the GitHub App's own bot user, e.g.
// "ariane[bot]". The login is a property of the app itself and never changes while the
// process runs, so it is resolved once at startup and handed to the handlers that need
// it. Retrieving the app requires app authentication rather than installation
// authentication, hence the dedicated client.
func ResolveAppBotLogin(ctx context.Context, clientCreator githubapp.ClientCreator) (string, error) {
	client, err := clientCreator.NewAppClient()
	if err != nil {
		return "", fmt.Errorf("failed to create app client: %w", err)
	}

	app, _, err := client.Apps.Get(ctx, "")
	if err != nil {
		return "", fmt.Errorf("failed to retrieve app: %w", err)
	}

	if app.GetSlug() == "" {
		return "", errors.New("app has no slug")
	}

	return app.GetSlug() + "[bot]", nil
}

func rerunFailedJobs(ctx context.Context, client *github.Client, owner, repo string, runID int64, workflowName string, logger zerolog.Logger) error {
	jobListOpts := &github.ListWorkflowJobsOptions{
		Filter:      "latest",
		ListOptions: github.ListOptions{PerPage: 100},
	}

	jobs, _, err := client.Actions.ListWorkflowJobs(ctx, owner, repo, runID, jobListOpts)
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to list workflow jobs for run ID %d", runID)
		return err
	}

	hasFailedJobs := false
	for _, job := range jobs.Jobs {
		if job.GetConclusion() == "failure" {
			hasFailedJobs = true
			logger.Debug().Msgf("Found failed job: %s (ID: %d)", job.GetName(), job.GetID())
			break
		}
	}

	if !hasFailedJobs {
		logger.Debug().Msgf("No failed jobs found for workflow '%s' (run ID: %d)", workflowName, runID)
		return nil
	}

	logger.Info().Msgf("Re-running failed jobs for workflow '%s' (run ID: %d)", workflowName, runID)
	if _, err := client.Actions.RerunFailedJobsByID(ctx, owner, repo, runID); err != nil {
		logger.Error().Err(err).Msgf("Failed to re-run workflow '%s' (run ID: %d)", workflowName, runID)
		return err
	}

	logger.Info().Msgf("Successfully triggered rerun for failed jobs in workflow '%s' (run ID: %d)", workflowName, runID)
	return nil
}

func prHasLabel(ctx context.Context, client *github.Client, pr *github.PullRequest, labelName string, logger zerolog.Logger) (bool, error) {
	if pr == nil {
		return false, nil
	}

	for _, label := range pr.Labels {
		if label.GetName() == labelName {
			return true, nil
		}
	}

	return false, nil
}

func commentOnPullRequest(ctx context.Context, client *github.Client, owner, repo string, prNumber int, commentBody string, logger zerolog.Logger) error {
	comment := &github.IssueComment{
		Body: github.Ptr(commentBody),
	}
	_, _, err := client.Issues.CreateComment(ctx, owner, repo, prNumber, comment)
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to create comment on PR %d", prNumber)
		return err
	}
	logger.Info().Msgf("Successfully posted comment on PR #%d", prNumber)
	return nil
}

func getWorkflowRuns(ctx context.Context, client *github.Client, owner, repo, workflow, sha string, logger zerolog.Logger) (*github.WorkflowRuns, error) {
	options := &github.ListWorkflowRunsOptions{HeadSHA: sha}
	workflowRuns, _, err := client.Actions.ListWorkflowRunsByFileName(ctx, owner, repo, workflow, options)
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to list workflow runs for workflow %s and SHA %s", workflow, sha)
		return nil, err
	}
	return workflowRuns, nil
}

func getComments(ctx context.Context, client *github.Client, owner, repo string, prNumber int, logger zerolog.Logger, since time.Time, count int) ([]*github.IssueComment, error) {
	// we are using IssueComments because PullRequestComments API is bugged and returns only empty responses
	options := &github.IssueListCommentsOptions{Since: &since, ListOptions: github.ListOptions{PerPage: count}}
	comments, _, err := client.Issues.ListComments(ctx, owner, repo, prNumber, options)
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to list comments for PR %v", prNumber)
		return nil, err
	}
	return comments, nil
}

func buildWorkflowStatusTable(workflowStatuses []workflowStatus) string {
	if len(workflowStatuses) == 0 {
		return ""
	}

	var commentBuilder strings.Builder
	commentBuilder.WriteString("## Workflow Status\n\n")
	commentBuilder.WriteString("| Workflow | Status |\n")
	commentBuilder.WriteString("|----------|--------|\n")

	for _, ws := range workflowStatuses {
		statusEmoji := getStatusEmoji(ws.status)
		fmt.Fprintf(&commentBuilder, "| `%s` | %s |\n", ws.name, statusEmoji)
	}

	return commentBuilder.String()
}

func getStatusEmoji(status workflowStatusType) string {
	switch status {
	case workflowStatusTriggered:
		return "✅ Triggered"
	case workflowStatusSkipped:
		return "⏭️ Skipped"
	case workflowStatusAlreadyCompleted:
		return "✔️ Already Completed"
	case workflowStatusFailed:
		return "❌ Failed to Trigger"
	case workflowStatusFailedToMarkSkipped:
		return "⚠️ Failed to Mark as Skipped"
	default:
		return string(status)
	}
}

// isAllowedTeamMember uses the "Get team membership for a user" to infer if a user can run Ariane
// See https://docs.github.com/en/rest/teams/members?apiVersion=2022-11-28#get-team-membership-for-a-user
func isAllowedTeamMember(ctx context.Context, client *github.Client, config *config.ArianeConfig, owner, author string, logger zerolog.Logger) bool {
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
