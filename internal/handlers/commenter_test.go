// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-github/v88/github"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestGithubCommenter_ReactionsDisabled(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected reaction request to %s", r.URL.Path)
	}))
	defer mockServer.Close()

	mockURL := new(mockServer.URL + "/")
	client, err := github.NewClient(github.WithURLs(mockURL, mockURL))
	assert.NoError(t, err)

	commenter := NewGithubCommenter(client, "owner", "repo", zerolog.Nop())
	commenter.setReactionsEnabled(false)

	// Assert that calling the reaction functions doesn't result in a call to
	// the GitHub API when reactions are disabled.
	assert.NoError(t, commenter.reactToComment(context.Background(), 1, "eyes"))
	assert.NoError(t, commenter.reactToPR(context.Background(), 1, "rocket"))
}
