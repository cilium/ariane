// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package handlers

import (
	"context"

	"github.com/google/go-github/v83/github"
	"github.com/rs/zerolog"
)

type GithubCommenter struct {
	client *github.Client
	owner  string
	repo   string
	logger zerolog.Logger
}

func NewGithubCommenter(client *github.Client, owner, repo string, logger zerolog.Logger) *GithubCommenter {
	return &GithubCommenter{
		client: client,
		owner:  owner,
		repo:   repo,
		logger: logger,
	}
}

func (c *GithubCommenter) commentOnPullRequest(ctx context.Context, prNumber int, replyBody string) error {
	comment := &github.IssueComment{
		Body: github.Ptr(replyBody),
	}
	_, _, err := c.client.Issues.CreateComment(ctx, c.owner, c.repo, prNumber, comment)
	if err != nil {
		c.logger.Error().Err(err).Msgf("Failed to create comment %s on PR %d", replyBody, prNumber)
		return err
	}
	return nil
}

func (c *GithubCommenter) reactToComment(ctx context.Context, commentID int64, emoji string) error {
	if emoji == "" {
		emoji = "rocket"
	}
	if _, _, err := c.client.Reactions.CreateIssueCommentReaction(ctx, c.owner, c.repo, commentID, emoji); err != nil {
		c.logger.Error().Err(err).Msgf("Failed to react to comment with %s emoji", emoji)
		return err
	}
	return nil
}

func (c *GithubCommenter) reactToPR(ctx context.Context, prNumber int, emoji string) error {
	if emoji == "" {
		emoji = "rocket"
	}
	if _, _, err := c.client.Reactions.CreateIssueReaction(ctx, c.owner, c.repo, prNumber, emoji); err != nil {
		c.logger.Error().Err(err).Msgf("Failed to react to issue with %s emoji", emoji)
		return err
	}
	return nil
}
