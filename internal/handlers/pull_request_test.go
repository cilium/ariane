package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cilium/ariane/internal/config"
	"github.com/google/go-github/v88/github"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestPRHandle_IsInvalidBot(t *testing.T) {
	oldconfigGetArianeConfigFromRepository := configGetArianeConfigFromRepository
	defer func() { configGetArianeConfigFromRepository = oldconfigGetArianeConfigFromRepository }()

	configGetArianeConfigFromRepository = mockGetArianeConfigFromRepository

	mockServer := setMockServerPullRequest()
	defer mockServer.Close()
	mockURL := github.Ptr(mockServer.URL + "/")
	client, err := github.NewClient(github.WithURLs(mockURL, mockURL))
	if err != nil {
		t.Fatalf("Failed to create GitHub client: %v", err)
	}

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(0)).Return(client, nil)

	handler := &PullRequestHandler{
		ClientCreator:    mockClientCreator,
		RunDelay:         time.Second,
		MaxRetryAttempts: config.DefaultMaxRetryAttempts,
	}

	payload := []byte(`{
  "action": "synchronize",
  "number": 101,
  "pull_request": {
    "number": 201,
    "state": "open",
    "title": "title",
    "user": {
      "login": "other[bot]"
    }
  },
  "repository": {
    "id": 1,
    "name": "repo",
    "full_name": "owner/repo",
    "owner": {
      "login": "owner",
      "type": "Organization",
      "user_view_type": "public",
      "site_admin": false
    }
  }
}`)

	err = handler.Handle(context.Background(), "pull_request", "deliveryID", payload)
	assert.Error(t, err)
}

func TestPRHandle_IsValidBot(t *testing.T) {
	oldconfigGetArianeConfigFromRepository := configGetArianeConfigFromRepository
	defer func() { configGetArianeConfigFromRepository = oldconfigGetArianeConfigFromRepository }()

	configGetArianeConfigFromRepository = mockGetArianeConfigFromRepository

	mockServer := setMockServerPullRequest()
	defer mockServer.Close()
	mockURL := github.Ptr(mockServer.URL + "/")
	client, err := github.NewClient(github.WithURLs(mockURL, mockURL))
	if err != nil {
		t.Fatalf("Failed to create GitHub client: %v", err)
	}

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(0)).Return(client, nil)

	handler := &PullRequestHandler{
		ClientCreator:    mockClientCreator,
		RunDelay:         time.Second,
		MaxRetryAttempts: config.DefaultMaxRetryAttempts,
	}

	payload := []byte(`{
  "action": "synchronize",
  "number": 201,
  "pull_request": {
    "number": 101,
    "state": "open",
    "title": "title",
    "user": {
      "login": "owner[bot]"
    }
  },
  "repository": {
    "id": 1,
    "name": "repo",
    "full_name": "owner/repo",
    "owner": {
      "login": "owner",
      "type": "Organization",
      "user_view_type": "public",
      "site_admin": false
    }
  }
}`)

	err = handler.Handle(context.Background(), "pull_request", "deliveryID", payload)
	assert.NoError(t, err)
}

func TestPRHandle_TrustedAuthor(t *testing.T) {
	oldconfigGetArianeConfigFromRepository := configGetArianeConfigFromRepository
	defer func() { configGetArianeConfigFromRepository = oldconfigGetArianeConfigFromRepository }()

	configGetArianeConfigFromRepository = mockGetArianeConfigFromRepository

	mockServer := setMockServerPullRequest()
	defer mockServer.Close()
	mockURL := github.Ptr(mockServer.URL + "/")
	client, err := github.NewClient(github.WithURLs(mockURL, mockURL))
	if err != nil {
		t.Fatalf("Failed to create GitHub client: %v", err)
	}

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(0)).Return(client, nil)

	handler := &PullRequestHandler{
		ClientCreator:    mockClientCreator,
		RunDelay:         time.Second,
		MaxRetryAttempts: config.DefaultMaxRetryAttempts,
	}

	payload := []byte(`{
  "action": "synchronize",
  "number": 301,
  "pull_request": {
    "number": 301,
    "state": "open",
    "title": "title",
    "user": {
      "login": "owner"
    }
  },
  "repository": {
    "id": 1,
    "name": "repo",
    "full_name": "owner/repo",
    "owner": {
      "login": "owner",
      "type": "Organization",
      "user_view_type": "public",
      "site_admin": false
    }
  }
}`)

	err = handler.Handle(context.Background(), "pull_request", "deliveryID", payload)
	assert.NoError(t, err)
}

func TestPRHandle_UntrustedAuthor(t *testing.T) {
	oldconfigGetArianeConfigFromRepository := configGetArianeConfigFromRepository
	defer func() { configGetArianeConfigFromRepository = oldconfigGetArianeConfigFromRepository }()

	configGetArianeConfigFromRepository = mockGetArianeConfigFromRepository

	mockServer := setMockServerPullRequest()
	defer mockServer.Close()
	mockURL := github.Ptr(mockServer.URL + "/")
	client, err := github.NewClient(github.WithURLs(mockURL, mockURL))
	if err != nil {
		t.Fatalf("Failed to create GitHub client: %v", err)
	}

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(0)).Return(client, nil)

	handler := &PullRequestHandler{
		ClientCreator:    mockClientCreator,
		RunDelay:         time.Second,
		MaxRetryAttempts: config.DefaultMaxRetryAttempts,
	}

	payload := []byte(`{
  "action": "synchronize",
  "number": 401,
  "pull_request": {
    "number": 401,
    "state": "open",
    "title": "title",
    "user": {
      "login": "untrustedauthor"
    }
  },
  "repository": {
    "id": 1,
    "name": "repo",
    "full_name": "owner/repo",
    "owner": {
      "login": "owner",
      "type": "Organization",
      "user_view_type": "public",
      "site_admin": false
    }
  }
}`)

	err = handler.Handle(context.Background(), "pull_request", "deliveryID", payload)
	assert.Error(t, err)
}

// markerCalls records what a pendingMarkerMux was asked to do with the pending marker.
type markerCalls struct {
	listed  bool
	removed bool
}

// pendingMarkerMux serves a PR whose comment 55 carries a pending marker left by Ariane,
// and records the calls made against that marker.
func pendingMarkerMux(t *testing.T, comments []*github.IssueComment, calls *markerCalls) *http.ServeMux {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/pulls/101", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(&github.PullRequest{
			Number: github.Ptr(101),
			State:  github.Ptr("open"),
			User:   &github.User{Login: github.Ptr("owner[bot]")},
			Head: &github.PullRequestBranch{
				Ref:  github.Ptr("pr/owner/mybugfix"),
				SHA:  github.Ptr("mock-sha"),
				Repo: &github.Repository{Owner: &github.User{Login: github.Ptr("owner")}, Name: github.Ptr("repo")},
			},
			Base: &github.PullRequestBranch{Ref: github.Ptr("main")},
		})
	})
	mux.HandleFunc("/repos/owner/repo/issues/101/comments", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(comments)
	})
	mux.HandleFunc("/repos/owner/repo/issues/comments/55/reactions", func(w http.ResponseWriter, r *http.Request) {
		calls.listed = true
		_ = json.NewEncoder(w).Encode([]*github.Reaction{
			{ID: github.Ptr[int64](99), User: &github.User{Login: github.Ptr(testAppBotLogin)}},
		})
	})
	mux.HandleFunc("/repos/owner/repo/issues/comments/55/reactions/99", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		calls.removed = true
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /repos/owner/repo/issues/101/reactions", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(&github.Reaction{ID: github.Ptr[int64](1)})
	})
	return mux
}

func TestClearPendingTriggerMarkers(t *testing.T) {
	testCases := []struct {
		name            string
		comment         *github.IssueComment
		expectedListed  bool
		expectedRemoved bool
	}{
		{
			name:            "pending command",
			comment:         &github.IssueComment{ID: github.Ptr[int64](55), Body: github.Ptr("/test")},
			expectedListed:  true,
			expectedRemoved: true,
		},
		{
			name:            "comment that only mentions a command",
			comment:         &github.IssueComment{ID: github.Ptr[int64](55), Body: github.Ptr("we should /test this")},
			expectedRemoved: false,
		},
		{
			name:            "unrelated comment",
			comment:         &github.IssueComment{ID: github.Ptr[int64](55), Body: github.Ptr("looks good to me")},
			expectedRemoved: false,
		},
		{
			// The reaction summary rules the comment out on its own.
			name: "command carrying no thumbs up at all",
			comment: &github.IssueComment{
				ID:        github.Ptr[int64](55),
				Body:      github.Ptr("/test"),
				Reactions: &github.Reactions{PlusOne: github.Ptr(0)},
			},
			expectedRemoved: false,
		},
		{
			name: "command carrying a thumbs up",
			comment: &github.IssueComment{
				ID:        github.Ptr[int64](55),
				Body:      github.Ptr("/test"),
				Reactions: &github.Reactions{PlusOne: github.Ptr(1)},
			},
			expectedListed:  true,
			expectedRemoved: true,
		},
	}

	arianeConfig, err := mockGetArianeConfigFromRepositoryWithFeedback(false, false)(nil, context.Background(), "owner", "repo", "main")
	if err != nil {
		t.Fatalf("Failed to build Ariane config: %v", err)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var calls markerCalls
			mux := pendingMarkerMux(t, []*github.IssueComment{tc.comment}, &calls)
			server := httptest.NewServer(mux)
			defer server.Close()

			mockURL := github.Ptr(server.URL + "/")
			client, err := github.NewClient(github.WithURLs(mockURL, mockURL))
			if err != nil {
				t.Fatalf("Failed to create GitHub client: %v", err)
			}

			commenter := NewGithubCommenter(client, "owner", "repo", zerolog.Nop())
			err = clearPendingTriggerMarkers(context.Background(), client, commenter, arianeConfig, "owner", "repo", 101, testAppBotLogin, zerolog.Nop())
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedListed, calls.listed, "reaction lookup")
			assert.Equal(t, tc.expectedRemoved, calls.removed, "marker removal")
		})
	}
}

func TestPRHandle_PendingMarkersClearedOnlyOnPush(t *testing.T) {
	testCases := []struct {
		name            string
		action          string
		expectedRemoved bool
	}{
		{name: "new commits pushed", action: "synchronize", expectedRemoved: true},
		{name: "pull request opened", action: "opened", expectedRemoved: false},
		{name: "pull request reopened", action: "reopened", expectedRemoved: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			oldconfigGetArianeConfigFromRepository := configGetArianeConfigFromRepository
			defer func() { configGetArianeConfigFromRepository = oldconfigGetArianeConfigFromRepository }()
			configGetArianeConfigFromRepository = mockGetArianeConfigFromRepositoryWithFeedback(false, false)

			var calls markerCalls
			comments := []*github.IssueComment{{ID: github.Ptr[int64](55), Body: github.Ptr("/test")}}
			server := httptest.NewServer(pendingMarkerMux(t, comments, &calls))
			defer server.Close()

			mockURL := github.Ptr(server.URL + "/")
			client, err := github.NewClient(github.WithURLs(mockURL, mockURL))
			if err != nil {
				t.Fatalf("Failed to create GitHub client: %v", err)
			}

			mockClientCreator := NewMockClientCreator(gomock.NewController(t))
			mockClientCreator.EXPECT().NewInstallationClient(int64(0)).Return(client, nil)

			handler := &PullRequestHandler{
				ClientCreator:    mockClientCreator,
				RunDelay:         time.Second,
				MaxRetryAttempts: config.DefaultMaxRetryAttempts,
				AppBotLogin:      testAppBotLogin,
			}

			payload := []byte(`{
  "action": "` + tc.action + `",
  "number": 101,
  "pull_request": {
    "number": 101,
    "state": "open",
    "title": "title",
    "user": {
      "login": "owner[bot]"
    }
  },
  "repository": {
    "id": 1,
    "name": "repo",
    "full_name": "owner/repo",
    "owner": {
      "login": "owner",
      "type": "Organization"
    }
  }
}`)

			assert.NoError(t, handler.Handle(context.Background(), "pull_request", "deliveryID", payload))
			assert.Equal(t, tc.expectedRemoved, calls.removed)
		})
	}
}

func setMockServerPullRequest() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/pulls/{number}", func(w http.ResponseWriter, r *http.Request) {

		number := r.PathValue("number")
		username := "owner"

		switch number {
		case "101":
			username = "owner[bot]"
		case "201":
			username = "other[bot]"
		case "301":
			username = "trustedauthor"
		case "401":
			username = "untrustedauthor"

		}
		pr := &github.PullRequest{
			User:  &github.User{Login: github.Ptr(username)},
			State: github.Ptr("open"),
			Head: &github.PullRequestBranch{
				Ref: github.Ptr("pr/owner/mybugfix"),
				SHA: github.Ptr("mock-sha"),
				Repo: &github.Repository{
					Owner: &github.User{Login: github.Ptr("owner")},
					Name:  github.Ptr("repo"),
				},
			},
			Base: &github.PullRequestBranch{
				Ref: github.Ptr("main"),
			},
		}
		if err := json.NewEncoder(w).Encode(pr); err != nil {
			http.Error(w, "setMockServer: could not encode the PR payload in JSON for the HTTP response.", http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("/orgs/owner/teams/organization-members/memberships/{author}", func(w http.ResponseWriter, r *http.Request) {
		author := r.PathValue("author")
		var membership *github.Membership

		switch author {
		case "trustedauthor":
			membership = &github.Membership{
				State: github.Ptr("active"),
			}
		case "unknownauthor":
			membership = &github.Membership{
				State: github.Ptr("pending"),
			}
		}

		if err := json.NewEncoder(w).Encode(membership); err != nil {
			http.Error(w, "setMockServer: could not encode the membership payload in JSON for the HTTP response.", http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("POST /repos/owner/repo/issues/{number}/reactions", func(w http.ResponseWriter, r *http.Request) {
		// https://docs.github.com/en/rest/reactions/reactions?apiVersion=2022-11-28#create-reaction-for-an-issue-comment
		reaction := &github.Reaction{
			ID:      github.Ptr(int64(1)),
			Content: github.Ptr(r.PostFormValue("content")),
		}
		if err := json.NewEncoder(w).Encode(reaction); err != nil {
			http.Error(w, "setMockServer: could not encode the reaction payload in JSON for the HTTP response.", http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/repos/owner/repo/pulls/{number}/files", func(w http.ResponseWriter, r *http.Request) {
		files := []*github.CommitFile{
			{Filename: github.Ptr("test.go")},
		}
		_ = json.NewEncoder(w).Encode(files)
	})

	return httptest.NewServer(mux)
}
