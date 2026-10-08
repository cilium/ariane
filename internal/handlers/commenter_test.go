// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-github/v88/github"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

// testAppBotLogin is the login ResolveAppBotLogin returns for Ariane, the one the handlers
// pass to findReaction to recognize the reactions Ariane itself left.
const testAppBotLogin = "ariane[bot]"

func newTestCommenter(t *testing.T, mux *http.ServeMux) *GithubCommenter {
	t.Helper()

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	mockURL := github.Ptr(server.URL + "/")
	client, err := github.NewClient(github.WithURLs(mockURL, mockURL))
	if err != nil {
		t.Fatalf("Failed to create GitHub client: %v", err)
	}

	return NewGithubCommenter(client, "owner", "repo", zerolog.Nop())
}

func TestGithubCommenter_FindReaction(t *testing.T) {
	testCases := []struct {
		name               string
		reactions          []*github.Reaction
		status             int
		expectedReactionID int64
		expectError        bool
	}{
		{
			name: "reaction left by Ariane",
			reactions: []*github.Reaction{
				{ID: github.Ptr[int64](42), User: &github.User{Login: github.Ptr(testAppBotLogin)}},
			},
			expectedReactionID: 42,
		},
		{
			name: "reaction left by a human",
			reactions: []*github.Reaction{
				{ID: github.Ptr[int64](42), User: &github.User{Login: github.Ptr("contributor")}},
			},
			expectedReactionID: 0,
		},
		{
			name: "reaction left by another bot of the organization",
			reactions: []*github.Reaction{
				{ID: github.Ptr[int64](42), User: &github.User{Login: github.Ptr("owner-renovate[bot]")}},
			},
			expectedReactionID: 0,
		},
		{
			name: "Ariane among several reactors",
			reactions: []*github.Reaction{
				{ID: github.Ptr[int64](7), User: &github.User{Login: github.Ptr("contributor")}},
				{ID: github.Ptr[int64](42), User: &github.User{Login: github.Ptr(testAppBotLogin)}},
			},
			expectedReactionID: 42,
		},
		{
			name:               "no reactions at all",
			reactions:          []*github.Reaction{},
			expectedReactionID: 0,
		},
		{
			name:        "API failure",
			status:      http.StatusInternalServerError,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var requestedContent string

			mux := http.NewServeMux()
			mux.HandleFunc("/repos/owner/repo/issues/comments/123/reactions", func(w http.ResponseWriter, r *http.Request) {
				if tc.status != 0 {
					w.WriteHeader(tc.status)
					return
				}
				requestedContent = r.URL.Query().Get("content")
				_ = json.NewEncoder(w).Encode(tc.reactions)
			})

			reactionID, err := newTestCommenter(t, mux).findReaction(context.Background(), 123, "+1", testAppBotLogin)
			if tc.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedReactionID, reactionID)
			assert.Equal(t, "+1", requestedContent, "reactions should be filtered by emoji server-side")
		})
	}
}

func TestGithubCommenter_RemoveReaction(t *testing.T) {
	testCases := []struct {
		name        string
		status      int
		expectError bool
	}{
		{name: "reaction removed", status: http.StatusNoContent},
		{name: "API failure", status: http.StatusInternalServerError, expectError: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			called := false

			mux := http.NewServeMux()
			mux.HandleFunc("/repos/owner/repo/issues/comments/123/reactions/42", func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodDelete, r.Method)
				called = true
				w.WriteHeader(tc.status)
			})

			err := newTestCommenter(t, mux).removeReaction(context.Background(), 123, 42)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.True(t, called, "the reaction deletion endpoint should have been called")
		})
	}
}
