// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package handlers

import (
	"context"

	"github.com/google/go-github/v88/github"
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

// findReaction returns the ID of the reaction with the given emoji left on the comment
// by login, or 0 if there is none. Callers pass Ariane's own bot login, as returned by
// appBotLogin: an organization may run other bots, and their reactions must not be
// mistaken for ours.
func (c *GithubCommenter) findReaction(ctx context.Context, commentID int64, emoji, login string) (int64, error) {
	opts := &github.ListReactionOptions{Content: emoji, ListOptions: github.ListOptions{PerPage: 100}}
	for {
		reactions, response, err := c.client.Reactions.ListIssueCommentReactions(ctx, c.owner, c.repo, commentID, opts)
		if err != nil {
			c.logger.Error().Err(err).Msgf("Failed to list %s reactions on comment %d", emoji, commentID)
			return 0, err
		}
		for _, reaction := range reactions {
			if reaction.GetUser().GetLogin() == login {
				return reaction.GetID(), nil
			}
		}
		if response.NextPage == 0 {
			return 0, nil
		}
		opts.Page = response.NextPage
	}
}

// removeReaction removes a previously created reaction from a comment.
func (c *GithubCommenter) removeReaction(ctx context.Context, commentID, reactionID int64) error {
	if _, err := c.client.Reactions.DeleteIssueCommentReaction(ctx, c.owner, c.repo, commentID, reactionID); err != nil {
		c.logger.Error().Err(err).Msgf("Failed to remove reaction %d from comment %d", reactionID, commentID)
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
