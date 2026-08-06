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
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

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

func setMockServerPullRequest() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/pulls/{number}", func(w http.ResponseWriter, r *http.Request) {

		number := r.PathValue("number")
		username := "owner"

		switch number {
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
