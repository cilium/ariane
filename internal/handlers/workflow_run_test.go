// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-github/v83/github"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestWorkflowRunHandler_Handles(t *testing.T) {
	handler := &WorkflowRunHandler{}
	handles := handler.Handles()
	assert.Equal(t, []string{"workflow_run"}, handles)
}

func TestWorkflowRunHandler_ActionNotCompleted(t *testing.T) {
	handler := &WorkflowRunHandler{}

	payload := []byte(`{
		"action": "requested",
		"workflow_run": {
			"id": 123
		},
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		}
	}`)

	err := handler.Handle(context.Background(), "workflow_run", "deliveryID", payload)
	assert.NoError(t, err)
}

func TestWorkflowRunHandler_ConclusionCancelled(t *testing.T) {
	handler := &WorkflowRunHandler{}

	payload := []byte(`{
		"action": "completed",
		"workflow_run": {
			"id": 123,
			"conclusion": "cancelled"
		},
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"installation": {
			"id": 1
		}
	}`)

	err := handler.Handle(context.Background(), "workflow_run", "deliveryID", payload)
	assert.NoError(t, err)
}

func TestWorkflowRunHandler_NoPullRequests(t *testing.T) {
	handler := &WorkflowRunHandler{}

	payload := []byte(`{
		"action": "completed",
		"workflow_run": {
			"id": 123,
			"conclusion": "success",
			"pull_requests": []
		},
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"installation": {
			"id": 1
		}
	}`)

	err := handler.Handle(context.Background(), "workflow_run", "deliveryID", payload)
	assert.NoError(t, err)
}

func TestWorkflowRunHandler_InvalidPayload(t *testing.T) {
	handler := &WorkflowRunHandler{}

	payload := []byte(`invalid json`)

	err := handler.Handle(context.Background(), "workflow_run", "deliveryID", payload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse workflow_run event payload")
}

func TestWorkflowRunHandler_UnauthorizedPRCreator(t *testing.T) {
	testCases := []struct {
		name     string
		username string
	}{
		{"regular user", "some-random-user"},
		{"missing prefix", "renovate[bot]"},
		{"missing suffix", "owner-renovate"},
		{"wrong suffix", "owner-bot"},
		{"wrong prefix", "other-renovate[bot]"},
		{"empty username", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test server for GitHub API
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()

			// Mock PR endpoint - PR created by unauthorized user
			mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, r *http.Request) {
				pr := &github.PullRequest{
					Number: github.Ptr(1),
					User: &github.User{
						Login: github.Ptr(tc.username),
					},
				}
				_ = json.NewEncoder(w).Encode(pr)
			})

			client := github.NewClient(nil)
			baseURL, _ := url.Parse(server.URL + "/")
			client.BaseURL = baseURL

			mockCtrl := gomock.NewController(t)
			mockClientCreator := NewMockClientCreator(mockCtrl)
			mockClientCreator.EXPECT().NewInstallationClient(int64(1)).Return(client, nil)

			handler := &WorkflowRunHandler{
				ClientCreator: mockClientCreator,
			}

			payload := []byte(`{
				"action": "completed",
				"workflow_run": {
					"conclusion": "success",
					"pull_requests": [
						{
							"number": 1
						}
					]
				},
				"repository": {
					"owner": {
						"login": "owner"
					},
					"name": "repo"
				},
				"installation": {
					"id": 1
				}
			}`)

			err := handler.Handle(context.Background(), "workflow_run", "deliveryID", payload)
			assert.NoError(t, err)
		})
	}
}

// Tests for successful workflow runs (staged runner functionality)

func TestWorkflowRunHandler_Success_NoStagesConfigured(t *testing.T) {
	// Create test server for GitHub API
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	// Mock PR endpoint
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		pr := &github.PullRequest{
			Number: github.Ptr(1),
			User: &github.User{
				Login: github.Ptr("owner-renovate[bot]"),
			},
			Base: &github.PullRequestBranch{
				Ref: github.Ptr("main"),
			},
		}
		_ = json.NewEncoder(w).Encode(pr)
	})

	// Mock labels endpoint
	mux.HandleFunc("/repos/owner/repo/issues/1/labels", func(w http.ResponseWriter, r *http.Request) {
		labels := []*github.Label{
			{Name: github.Ptr("auto-cicd")},
		}
		_ = json.NewEncoder(w).Encode(labels)
	})

	// Mock config file endpoint - no stages configured
	mux.HandleFunc("/repos/owner/repo/contents/.github/ariane-config.yaml", func(w http.ResponseWriter, r *http.Request) {
		configContent := `
allowed-teams:
  - team1
triggers:
  /test:
    workflows:
      - foo.yaml
`
		content := &github.RepositoryContent{
			Content: github.Ptr(configContent),
		}
		_ = json.NewEncoder(w).Encode(content)
	})

	client := github.NewClient(nil)
	baseURL, _ := url.Parse(server.URL + "/")
	client.BaseURL = baseURL

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(1)).Return(client, nil)

	handler := &WorkflowRunHandler{
		ClientCreator: mockClientCreator,
	}

	payload := []byte(`{
		"action": "completed",
		"workflow": {
			"path": ".github/workflows/test.yaml"
		},
		"workflow_run": {
			"id": 123,
			"conclusion": "success",
			"pull_requests": [
				{
					"number": 1
				}
			]
		},
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"installation": {
			"id": 1
		}
	}`)

	err := handler.Handle(context.Background(), "workflow_run", "deliveryID", payload)
	assert.NoError(t, err)
}

func TestWorkflowRunHandler_Success_PRMissingLabel(t *testing.T) {
	// Create test server for GitHub API
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	// Mock PR endpoint
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		pr := &github.PullRequest{
			Number: github.Ptr(1),
			User: &github.User{
				Login: github.Ptr("owner-renovate[bot]"),
			},
			Base: &github.PullRequestBranch{
				Ref: github.Ptr("main"),
			},
		}
		_ = json.NewEncoder(w).Encode(pr)
	})

	// Mock labels endpoint - no auto-cicd label
	mux.HandleFunc("/repos/owner/repo/issues/1/labels", func(w http.ResponseWriter, r *http.Request) {
		labels := []*github.Label{
			{Name: github.Ptr("bug")},
		}
		_ = json.NewEncoder(w).Encode(labels)
	})

	// Mock config file endpoint
	mux.HandleFunc("/repos/owner/repo/contents/.github/ariane-config.yaml", func(w http.ResponseWriter, r *http.Request) {
		configContent := `
stages-config:
  label: auto-cicd
  stages:
    - workflows:
      - test.yaml
      command: /test
`
		content := &github.RepositoryContent{
			Content: github.Ptr(configContent),
		}
		_ = json.NewEncoder(w).Encode(content)
	})

	client := github.NewClient(nil)
	baseURL, _ := url.Parse(server.URL + "/")
	client.BaseURL = baseURL

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(1)).Return(client, nil)

	handler := &WorkflowRunHandler{
		ClientCreator: mockClientCreator,
	}

	payload := []byte(`{
		"action": "completed",
		"workflow": {
			"path": ".github/workflows/test.yaml"
		},
		"workflow_run": {
			"id": 123,
			"conclusion": "success",
			"pull_requests": [
				{
					"number": 1
				}
			]
		},
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"installation": {
			"id": 1
		}
	}`)

	err := handler.Handle(context.Background(), "workflow_run", "deliveryID", payload)
	assert.NoError(t, err)
}

func TestWorkflowRunHandler_Success_SuccessfulCommentPostSingleWorkflow(t *testing.T) {
	// Create test server for GitHub API
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	commentPosted := false

	// Mock PR endpoint
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		pr := &github.PullRequest{
			Number: github.Ptr(1),
			User: &github.User{
				Login: github.Ptr("owner-renovate[bot]"),
			},
			Base: &github.PullRequestBranch{
				Ref: github.Ptr("main"),
			},
			Labels: []*github.Label{
				{Name: github.Ptr("auto-cicd")},
			},
		}
		_ = json.NewEncoder(w).Encode(pr)
	})

	// Mock config file endpoint
	mux.HandleFunc("/repos/owner/repo/contents/.github/ariane-config.yaml", func(w http.ResponseWriter, r *http.Request) {
		configContent := `
stages-config:
  label: auto-cicd
  stages:
    - workflows:
      - test.yaml
      command: /test
`
		content := &github.RepositoryContent{
			Content: github.Ptr(configContent),
		}
		_ = json.NewEncoder(w).Encode(content)
	})

	// Mock comment creation endpoint
	mux.HandleFunc("/repos/owner/repo/issues/1/comments", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			var comment github.IssueComment
			_ = json.NewDecoder(r.Body).Decode(&comment)
			assert.Equal(t, "/test", comment.GetBody())
			commentPosted = true
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(&github.IssueComment{ID: github.Ptr[int64](123)})
		}
	})

	client := github.NewClient(nil)
	baseURL, _ := url.Parse(server.URL + "/")
	client.BaseURL = baseURL

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(1)).Return(client, nil)

	mux.HandleFunc("/repos/owner/repo/actions/workflows/test.yaml/runs", func(w http.ResponseWriter, r *http.Request) {
		runs := &github.WorkflowRuns{
			WorkflowRuns: []*github.WorkflowRun{
				{Conclusion: github.Ptr("success")},
			},
		}
		_ = json.NewEncoder(w).Encode(runs)
	})

	handler := &WorkflowRunHandler{
		ClientCreator: mockClientCreator,
	}

	payload := []byte(`{
		"action": "completed",
		"workflow": {
			"path": ".github/workflows/test.yaml"
		},
		"workflow_run": {
			"id": 123,
			"conclusion": "success",
			"pull_requests": [
				{
					"number": 1
				}
			]
		},
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"installation": {
			"id": 1
		}
	}`)

	err := handler.Handle(context.Background(), "workflow_run", "deliveryID", payload)
	assert.NoError(t, err)
	assert.True(t, commentPosted, "Comment should have been posted")
}

func TestWorkflowRunHandler_Success_SuccessfulCommentPostTwoWorkflows(t *testing.T) {
	// Create test server for GitHub API
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	commentPosted := false
	var listedWorkflows []string

	// Mock PR endpoint
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		pr := &github.PullRequest{
			Number: github.Ptr(1),
			User: &github.User{
				Login: github.Ptr("owner-renovate[bot]"),
			},
			Base: &github.PullRequestBranch{
				Ref: github.Ptr("main"),
			},
			Labels: []*github.Label{
				{Name: github.Ptr("auto-cicd")},
			},
		}
		_ = json.NewEncoder(w).Encode(pr)
	})

	// Mock config file endpoint with two workflows in the same stage
	mux.HandleFunc("/repos/owner/repo/contents/.github/ariane-config.yaml", func(w http.ResponseWriter, r *http.Request) {
		configContent := `
stages-config:
  label: auto-cicd
  stages:
    - workflows:
      - test.yaml
      - test2.yaml
      command: /test
`
		content := &github.RepositoryContent{
			Content: github.Ptr(configContent),
		}
		_ = json.NewEncoder(w).Encode(content)
	})

	// Mock workflow-runs listing for both workflows and record which were queried
	mux.HandleFunc("/repos/owner/repo/actions/workflows/test.yaml/runs", func(w http.ResponseWriter, r *http.Request) {
		listedWorkflows = append(listedWorkflows, "test.yaml")
		runs := &github.WorkflowRuns{
			WorkflowRuns: []*github.WorkflowRun{
				{Conclusion: github.Ptr("success")},
			},
		}
		_ = json.NewEncoder(w).Encode(runs)
	})
	mux.HandleFunc("/repos/owner/repo/actions/workflows/test2.yaml/runs", func(w http.ResponseWriter, r *http.Request) {
		listedWorkflows = append(listedWorkflows, "test2.yaml")
		runs := &github.WorkflowRuns{
			WorkflowRuns: []*github.WorkflowRun{
				{Conclusion: github.Ptr("success")},
			},
		}
		_ = json.NewEncoder(w).Encode(runs)
	})

	// Mock comment creation endpoint
	mux.HandleFunc("/repos/owner/repo/issues/1/comments", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var comment github.IssueComment
			_ = json.NewDecoder(r.Body).Decode(&comment)
			assert.Equal(t, "/test", comment.GetBody())
			commentPosted = true
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(&github.IssueComment{ID: github.Ptr[int64](123)})
		}
	})

	client := github.NewClient(nil)
	baseURL, _ := url.Parse(server.URL + "/")
	client.BaseURL = baseURL

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(1)).Return(client, nil)

	handler := &WorkflowRunHandler{
		ClientCreator: mockClientCreator,
	}

	payload := []byte(`{
  "action": "completed",
  "workflow": {
    "path": ".github/workflows/test.yaml"
  },
  "workflow_run": {
    "id": 123,
    "head_sha": "deadbeef",
    "conclusion": "success",
    "pull_requests": [
      {
        "number": 1
      }
    ]
  },
  "repository": {
    "owner": {
      "login": "owner"
    },
    "name": "repo"
  },
  "installation": {
    "id": 1
  }
}`)
	err := handler.Handle(context.Background(), "workflow_run", "deliveryID", payload)
	assert.NoError(t, err)
	assert.True(t, commentPosted, "Comment should have been posted")
	assert.ElementsMatch(t, []string{"test.yaml", "test2.yaml"}, listedWorkflows, "both workflows should be checked")
}

func TestWorkflowRunHandler_Success_FailCommentPostTwoWorkflowsOneFailed(t *testing.T) {
	// Create test server for GitHub API
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	commentPosted := false
	var listedWorkflows []string

	// Mock PR endpoint
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		pr := &github.PullRequest{
			Number: github.Ptr(1),
			User: &github.User{
				Login: github.Ptr("owner-renovate[bot]"),
			},
			Base: &github.PullRequestBranch{
				Ref: github.Ptr("main"),
			},
			Labels: []*github.Label{
				{Name: github.Ptr("auto-cicd")},
			},
		}
		_ = json.NewEncoder(w).Encode(pr)
	})

	// Mock config file endpoint with two workflows in the same stage
	mux.HandleFunc("/repos/owner/repo/contents/.github/ariane-config.yaml", func(w http.ResponseWriter, r *http.Request) {
		configContent := `
stages-config:
  label: auto-cicd
  stages:
    - workflows:
      - test.yaml
      - test2.yaml
      command: /test
`
		content := &github.RepositoryContent{
			Content: github.Ptr(configContent),
		}
		_ = json.NewEncoder(w).Encode(content)
	})

	// Mock workflow-runs listing for both workflows and record which were queried
	mux.HandleFunc("/repos/owner/repo/actions/workflows/test.yaml/runs", func(w http.ResponseWriter, r *http.Request) {
		listedWorkflows = append(listedWorkflows, "test.yaml")
		runs := &github.WorkflowRuns{
			WorkflowRuns: []*github.WorkflowRun{
				{Conclusion: github.Ptr("success")},
			},
		}
		_ = json.NewEncoder(w).Encode(runs)
	})
	mux.HandleFunc("/repos/owner/repo/actions/workflows/test2.yaml/runs", func(w http.ResponseWriter, r *http.Request) {
		listedWorkflows = append(listedWorkflows, "test2.yaml")
		runs := &github.WorkflowRuns{
			WorkflowRuns: []*github.WorkflowRun{
				{Conclusion: github.Ptr("failure")},
			},
		}
		_ = json.NewEncoder(w).Encode(runs)
	})

	// Mock comment creation endpoint
	mux.HandleFunc("/repos/owner/repo/issues/1/comments", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var comment github.IssueComment
			_ = json.NewDecoder(r.Body).Decode(&comment)
			assert.Equal(t, "/test", comment.GetBody())
			commentPosted = true
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(&github.IssueComment{ID: github.Ptr[int64](123)})
		}
	})

	client := github.NewClient(nil)
	baseURL, _ := url.Parse(server.URL + "/")
	client.BaseURL = baseURL

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(1)).Return(client, nil)

	handler := &WorkflowRunHandler{
		ClientCreator: mockClientCreator,
	}

	payload := []byte(`{
  "action": "completed",
  "workflow": {
    "path": ".github/workflows/test.yaml"
  },
  "workflow_run": {
    "id": 123,
    "head_sha": "deadbeef",
    "conclusion": "success",
    "pull_requests": [
      {
        "number": 1
      }
    ]
  },
  "repository": {
    "owner": {
      "login": "owner"
    },
    "name": "repo"
  },
  "installation": {
    "id": 1
  }
}`)
	err := handler.Handle(context.Background(), "workflow_run", "deliveryID", payload)
	assert.NoError(t, err)
	assert.False(t, commentPosted, "Comment should have been posted")
	assert.ElementsMatch(t, []string{"test.yaml", "test2.yaml"}, listedWorkflows, "both workflows should be checked")
}

func TestWorkflowRunHandler_Success_DependencyTriggering(t *testing.T) {
	testCases := []struct {
		name          string
		comments      []github.IssueComment
		shouldTrigger bool
	}{
		{name: "no previous comments", comments: []github.IssueComment{}, shouldTrigger: false},
		{name: "previous comment in proper time window",
			comments: []github.IssueComment{
				{
					Body:      github.Ptr("/test"),
					CreatedAt: &github.Timestamp{Time: time.Now().Add(-1 * time.Hour)},
				},
			},
			shouldTrigger: true,
		},
		{name: "previous comment too young",
			comments: []github.IssueComment{
				{
					Body:      github.Ptr("/test"),
					CreatedAt: &github.Timestamp{Time: time.Now().Add(+1 * time.Minute).Add(recentCutoff)},
				},
			},
			shouldTrigger: false,
		},
	}
	// we are not testing the comment being too old because GH API filtering ensures that we won't get those comments at all

	for _, tc := range testCases {
		func() {
			// Create test server for GitHub API
			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()

			commentPosted := false
			var listedWorkflows []string

			// Mock PR endpoint
			mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, r *http.Request) {
				pr := &github.PullRequest{
					Number: github.Ptr(1),
					User: &github.User{
						Login: github.Ptr("owner-renovate[bot]"),
					},
					Base: &github.PullRequestBranch{
						Ref: github.Ptr("main"),
					},
					Labels: []*github.Label{
						{Name: github.Ptr("auto-cicd")},
					},
				}
				_ = json.NewEncoder(w).Encode(pr)
			})

			// Mock config file endpoint with two workflows in the same stage
			mux.HandleFunc("/repos/owner/repo/contents/.github/ariane-config.yaml", func(w http.ResponseWriter, r *http.Request) {
				configContent := `
triggers:
  /test:
    workflows:
    - test.yaml
    depends-on:
    - /dependency
  /dependency:
    workflows:
    - dependency.yaml
`
				content := &github.RepositoryContent{
					Content: github.Ptr(configContent),
				}
				_ = json.NewEncoder(w).Encode(content)
			})

			// Mock workflow-runs listing for both workflows and record which were queried
			mux.HandleFunc("/repos/owner/repo/actions/workflows/dependency.yaml/runs", func(w http.ResponseWriter, r *http.Request) {
				listedWorkflows = append(listedWorkflows, "dependency.yaml")
				runs := &github.WorkflowRuns{
					TotalCount: github.Ptr(1),
					WorkflowRuns: []*github.WorkflowRun{
						{Conclusion: github.Ptr("success")},
					},
				}
				_ = json.NewEncoder(w).Encode(runs)
			})

			// Mock comment creation endpoint
			mux.HandleFunc("/repos/owner/repo/issues/1/comments", func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					var comment github.IssueComment
					_ = json.NewDecoder(r.Body).Decode(&comment)
					assert.Equal(t, "/test", comment.GetBody())
					commentPosted = true
					w.WriteHeader(http.StatusCreated)
					_ = json.NewEncoder(w).Encode(&github.IssueComment{ID: github.Ptr[int64](123)})
				} else {
					_ = json.NewEncoder(w).Encode(tc.comments)
				}
			})

			client := github.NewClient(nil)
			baseURL, _ := url.Parse(server.URL + "/")
			client.BaseURL = baseURL

			mockCtrl := gomock.NewController(t)
			mockClientCreator := NewMockClientCreator(mockCtrl)
			mockClientCreator.EXPECT().NewInstallationClient(int64(1)).Return(client, nil)

			handler := &WorkflowRunHandler{
				ClientCreator: mockClientCreator,
			}

			payload := []byte(`{
  "action": "completed",
  "workflow": {
    "path": ".github/workflows/dependency.yaml"
  },
  "workflow_run": {
    "id": 123,
    "head_sha": "deadbeef",
    "conclusion": "success",
    "pull_requests": [
      {
        "number": 1
      }
    ],
    "path": ".github/workflows/dependency.yaml"
  },
  "repository": {
    "owner": {
      "login": "owner"
    },
    "name": "repo"
  },
  "installation": {
    "id": 1
  }
}`)
			err := handler.Handle(context.Background(), "workflow_run", "deliveryID", payload)
			assert.NoError(t, err)
			if tc.shouldTrigger {
				assert.True(t, commentPosted, "Comment should have been posted for case: %s", tc.name)
			} else {
				assert.False(t, commentPosted, "Comment should not have been posted for case: %s", tc.name)
			}
			assert.ElementsMatch(t, []string{"dependency.yaml"}, listedWorkflows, "both workflows should be checked")
		}()
	}
}

// Tests for failed workflow runs (rerun failed jobs functionality)

func TestWorkflowRunHandler_Failure_MaxRetriesReached(t *testing.T) {
	// Create test server for GitHub API
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	rerunCalled := false

	// Mock PR endpoint
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		pr := &github.PullRequest{
			Number: github.Ptr(1),
			User: &github.User{
				Login: github.Ptr("owner-renovate[bot]"),
			},
		}
		_ = json.NewEncoder(w).Encode(pr)
	})

	// Mock labels endpoint - has rerun-failed:2 label
	mux.HandleFunc("/repos/owner/repo/issues/1/labels", func(w http.ResponseWriter, r *http.Request) {
		labels := []*github.Label{
			{Name: github.Ptr("rerun-failed:2")},
		}
		_ = json.NewEncoder(w).Encode(labels)
	})

	// Mock workflow run endpoint - already at attempt 3 (exceeded max of 2)
	mux.HandleFunc("/repos/owner/repo/actions/runs/123", func(w http.ResponseWriter, r *http.Request) {
		run := &github.WorkflowRun{
			ID:         github.Ptr[int64](123),
			RunAttempt: github.Ptr(3),
		}
		_ = json.NewEncoder(w).Encode(run)
	})

	// Mock rerun endpoint (should not be called)
	mux.HandleFunc("/repos/owner/repo/actions/runs/123/rerun-failed-jobs", func(w http.ResponseWriter, r *http.Request) {
		rerunCalled = true
		w.WriteHeader(http.StatusCreated)
	})

	client := github.NewClient(nil)
	baseURL, _ := url.Parse(server.URL + "/")
	client.BaseURL = baseURL

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(1)).Return(client, nil)

	handler := &WorkflowRunHandler{
		ClientCreator: mockClientCreator,
	}

	payload := []byte(`{
		"action": "completed",
		"workflow": {
			"name": "test-workflow",
			"path": ".github/workflows/test.yaml"
		},
		"workflow_run": {
			"id": 123,
			"conclusion": "failure",
			"pull_requests": [
				{
					"number": 1
				}
			]
		},
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"installation": {
			"id": 1
		}
	}`)

	err := handler.Handle(context.Background(), "workflow_run", "deliveryID", payload)
	assert.NoError(t, err)
	assert.False(t, rerunCalled, "Rerun should not have been called when max retries reached")
}

func TestWorkflowRunHandler_Failure_NoFailedJobs(t *testing.T) {
	// Create test server for GitHub API
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	rerunCalled := false

	// Mock PR endpoint
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		pr := &github.PullRequest{
			Number: github.Ptr(1),
			User: &github.User{
				Login: github.Ptr("owner-release[bot]"),
			},
		}
		_ = json.NewEncoder(w).Encode(pr)
	})

	// Mock labels endpoint - has rerun-failed:3 label
	mux.HandleFunc("/repos/owner/repo/issues/1/labels", func(w http.ResponseWriter, r *http.Request) {
		labels := []*github.Label{
			{Name: github.Ptr("rerun-failed:3")},
		}
		_ = json.NewEncoder(w).Encode(labels)
	})

	// Mock workflow run endpoint - first attempt
	mux.HandleFunc("/repos/owner/repo/actions/runs/123", func(w http.ResponseWriter, r *http.Request) {
		run := &github.WorkflowRun{
			ID:         github.Ptr[int64](123),
			RunAttempt: github.Ptr(1),
		}
		_ = json.NewEncoder(w).Encode(run)
	})

	// Mock jobs endpoint - return no failed jobs (all successful)
	mux.HandleFunc("/repos/owner/repo/actions/runs/123/jobs", func(w http.ResponseWriter, r *http.Request) {
		jobs := &github.Jobs{
			TotalCount: github.Ptr(2),
			Jobs: []*github.WorkflowJob{
				{
					ID:         github.Ptr[int64](1),
					Name:       github.Ptr("test-job-1"),
					Conclusion: github.Ptr("success"),
				},
				{
					ID:         github.Ptr[int64](2),
					Name:       github.Ptr("test-job-2"),
					Conclusion: github.Ptr("success"),
				},
			},
		}
		_ = json.NewEncoder(w).Encode(jobs)
	})

	// Mock rerun endpoint (should not be called)
	mux.HandleFunc("/repos/owner/repo/actions/runs/123/rerun-failed-jobs", func(w http.ResponseWriter, r *http.Request) {
		rerunCalled = true
		w.WriteHeader(http.StatusCreated)
	})

	client := github.NewClient(nil)
	baseURL, _ := url.Parse(server.URL + "/")
	client.BaseURL = baseURL

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(1)).Return(client, nil)

	handler := &WorkflowRunHandler{
		ClientCreator: mockClientCreator,
	}

	payload := []byte(`{
		"action": "completed",
		"workflow": {
			"name": "test-workflow",
			"path": ".github/workflows/test.yaml"
		},
		"workflow_run": {
			"id": 123,
			"conclusion": "failure",
			"pull_requests": [
				{
					"number": 1
				}
			]
		},
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"installation": {
			"id": 1
		}
	}`)

	err := handler.Handle(context.Background(), "workflow_run", "deliveryID", payload)
	assert.NoError(t, err)
	assert.False(t, rerunCalled, "Rerun should not have been called when no jobs failed")
}

func TestWorkflowRunHandler_Failure_WorkflowNotInRerunList(t *testing.T) {
	// Create test server for GitHub API
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	rerunCalled := false

	// Mock PR endpoint
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		pr := &github.PullRequest{
			Number: github.Ptr(1),
			User: &github.User{
				Login: github.Ptr("owner-renovate[bot]"),
			},
			Base: &github.PullRequestBranch{
				Ref: github.Ptr("main"),
			},
		}
		_ = json.NewEncoder(w).Encode(pr)
	})

	// Mock config file endpoint - has rerun config with specific workflows
	mux.HandleFunc("/repos/owner/repo/contents/.github/ariane-config.yaml", func(w http.ResponseWriter, r *http.Request) {
		configContent := `
rerun:
  max-retries: 3
  workflows:
    - conformance-e2e.yaml
    - integration-test.yaml
`
		content := &github.RepositoryContent{
			Content: github.Ptr(configContent),
		}
		_ = json.NewEncoder(w).Encode(content)
	})

	// Mock rerun endpoint (should not be called)
	mux.HandleFunc("/repos/owner/repo/actions/runs/123/rerun-failed-jobs", func(w http.ResponseWriter, r *http.Request) {
		rerunCalled = true
		w.WriteHeader(http.StatusCreated)
	})

	client := github.NewClient(nil)
	baseURL, _ := url.Parse(server.URL + "/")
	client.BaseURL = baseURL

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(1)).Return(client, nil)

	handler := &WorkflowRunHandler{
		ClientCreator: mockClientCreator,
	}

	payload := []byte(`{
		"action": "completed",
		"workflow": {
			"name": "unit-tests",
			"path": ".github/workflows/unit-tests.yaml"
		},
		"workflow_run": {
			"id": 123,
			"conclusion": "failure",
			"pull_requests": [
				{
					"number": 1
				}
			]
		},
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"installation": {
			"id": 1
		}
	}`)

	err := handler.Handle(context.Background(), "workflow_run", "deliveryID", payload)
	assert.NoError(t, err)
	assert.False(t, rerunCalled, "Rerun should not have been called for workflow not in allowed list")
}

func TestWorkflowRunHandler_Failure_WorkflowInRerunList(t *testing.T) {
	// Create test server for GitHub API
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	rerunCalled := false

	// Mock PR endpoint
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		pr := &github.PullRequest{
			Number: github.Ptr(1),
			User: &github.User{
				Login: github.Ptr("owner-renovate[bot]"),
			},
			Base: &github.PullRequestBranch{
				Ref: github.Ptr("main"),
			},
		}
		_ = json.NewEncoder(w).Encode(pr)
	})

	// Mock config file endpoint - has rerun config with max-retries and specific workflows
	mux.HandleFunc("/repos/owner/repo/contents/.github/ariane-config.yaml", func(w http.ResponseWriter, r *http.Request) {
		configContent := `
rerun:
  max-retries: 3
  workflows:
    - conformance-e2e.yaml
    - integration-test.yaml
`
		content := &github.RepositoryContent{
			Content: github.Ptr(configContent),
		}
		_ = json.NewEncoder(w).Encode(content)
	})

	// Mock workflow run endpoint - first attempt
	mux.HandleFunc("/repos/owner/repo/actions/runs/123", func(w http.ResponseWriter, r *http.Request) {
		run := &github.WorkflowRun{
			ID:         github.Ptr[int64](123),
			RunAttempt: github.Ptr(1),
		}
		_ = json.NewEncoder(w).Encode(run)
	})

	// Mock jobs endpoint - return failed jobs
	mux.HandleFunc("/repos/owner/repo/actions/runs/123/jobs", func(w http.ResponseWriter, r *http.Request) {
		jobs := &github.Jobs{
			TotalCount: github.Ptr(2),
			Jobs: []*github.WorkflowJob{
				{
					ID:         github.Ptr[int64](1),
					Name:       github.Ptr("test-job-1"),
					Conclusion: github.Ptr("failure"),
				},
			},
		}
		_ = json.NewEncoder(w).Encode(jobs)
	})

	// Mock rerun endpoint
	mux.HandleFunc("/repos/owner/repo/actions/runs/123/rerun-failed-jobs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			rerunCalled = true
			w.WriteHeader(http.StatusCreated)
		}
	})

	client := github.NewClient(nil)
	baseURL, _ := url.Parse(server.URL + "/")
	client.BaseURL = baseURL

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(1)).Return(client, nil)

	handler := &WorkflowRunHandler{
		ClientCreator: mockClientCreator,
	}

	payload := []byte(`{
		"action": "completed",
		"workflow": {
			"name": "conformance-e2e",
			"path": ".github/workflows/conformance-e2e.yaml"
		},
		"workflow_run": {
			"id": 123,
			"conclusion": "failure",
			"pull_requests": [
				{
					"number": 1
				}
			]
		},
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"installation": {
			"id": 1
		}
	}`)

	err := handler.Handle(context.Background(), "workflow_run", "deliveryID", payload)
	assert.NoError(t, err)
	assert.True(t, rerunCalled, "Rerun should have been called for workflow in allowed list")
}

func TestWorkflowRunHandler_Failure_ConfigEnforcesMaxRetries(t *testing.T) {
	// Create test server for GitHub API
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	rerunCalled := false

	// Mock PR endpoint
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		pr := &github.PullRequest{
			Number: github.Ptr(1),
			User: &github.User{
				Login: github.Ptr("owner-renovate[bot]"),
			},
			Base: &github.PullRequestBranch{
				Ref: github.Ptr("main"),
			},
		}
		_ = json.NewEncoder(w).Encode(pr)
	})

	// Mock config file endpoint - max-retries is 2
	mux.HandleFunc("/repos/owner/repo/contents/.github/ariane-config.yaml", func(w http.ResponseWriter, r *http.Request) {
		configContent := `
rerun:
  max-retries: 2
`
		content := &github.RepositoryContent{
			Content: github.Ptr(configContent),
		}
		_ = json.NewEncoder(w).Encode(content)
	})

	// Mock workflow run endpoint - attempt 3 (exceeds config max of 2)
	mux.HandleFunc("/repos/owner/repo/actions/runs/123", func(w http.ResponseWriter, r *http.Request) {
		run := &github.WorkflowRun{
			ID:         github.Ptr[int64](123),
			RunAttempt: github.Ptr(3),
		}
		_ = json.NewEncoder(w).Encode(run)
	})

	// Mock rerun endpoint (should not be called because config enforces max of 2)
	mux.HandleFunc("/repos/owner/repo/actions/runs/123/rerun-failed-jobs", func(w http.ResponseWriter, r *http.Request) {
		rerunCalled = true
		w.WriteHeader(http.StatusCreated)
	})

	client := github.NewClient(nil)
	baseURL, _ := url.Parse(server.URL + "/")
	client.BaseURL = baseURL

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(1)).Return(client, nil)

	handler := &WorkflowRunHandler{
		ClientCreator: mockClientCreator,
	}

	payload := []byte(`{
		"action": "completed",
		"workflow": {
			"name": "test-workflow",
			"path": ".github/workflows/test.yaml"
		},
		"workflow_run": {
			"id": 123,
			"conclusion": "failure",
			"pull_requests": [
				{
					"number": 1
				}
			]
		},
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"installation": {
			"id": 1
		}
	}`)

	err := handler.Handle(context.Background(), "workflow_run", "deliveryID", payload)
	assert.NoError(t, err)
	assert.False(t, rerunCalled, "Rerun should not have been called because config enforces max of 2 (attempt 3 exceeds it)")
}

func TestWorkflowRunHandler_Failure_EmptyWorkflowsListAllowsAll(t *testing.T) {
	// Create test server for GitHub API
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	rerunCalled := false

	// Mock PR endpoint
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		pr := &github.PullRequest{
			Number: github.Ptr(1),
			User: &github.User{
				Login: github.Ptr("owner-renovate[bot]"),
			},
			Base: &github.PullRequestBranch{
				Ref: github.Ptr("main"),
			},
		}
		_ = json.NewEncoder(w).Encode(pr)
	})

	// Mock config file endpoint - empty workflows list should allow all workflows
	mux.HandleFunc("/repos/owner/repo/contents/.github/ariane-config.yaml", func(w http.ResponseWriter, r *http.Request) {
		configContent := `
rerun:
  max-retries: 3
  workflows: []
`
		content := &github.RepositoryContent{
			Content: github.Ptr(configContent),
		}
		_ = json.NewEncoder(w).Encode(content)
	})

	// Mock workflow run endpoint - first attempt
	mux.HandleFunc("/repos/owner/repo/actions/runs/123", func(w http.ResponseWriter, r *http.Request) {
		run := &github.WorkflowRun{
			ID:         github.Ptr[int64](123),
			RunAttempt: github.Ptr(1),
		}
		_ = json.NewEncoder(w).Encode(run)
	})

	// Mock jobs endpoint - return failed jobs
	mux.HandleFunc("/repos/owner/repo/actions/runs/123/jobs", func(w http.ResponseWriter, r *http.Request) {
		jobs := &github.Jobs{
			TotalCount: github.Ptr(2),
			Jobs: []*github.WorkflowJob{
				{
					ID:         github.Ptr[int64](1),
					Name:       github.Ptr("test-job-1"),
					Conclusion: github.Ptr("failure"),
				},
			},
		}
		_ = json.NewEncoder(w).Encode(jobs)
	})

	// Mock rerun endpoint (should be called since empty list allows all workflows)
	mux.HandleFunc("/repos/owner/repo/actions/runs/123/rerun-failed-jobs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			rerunCalled = true
			w.WriteHeader(http.StatusCreated)
		}
	})

	client := github.NewClient(nil)
	baseURL, _ := url.Parse(server.URL + "/")
	client.BaseURL = baseURL

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(1)).Return(client, nil)

	handler := &WorkflowRunHandler{
		ClientCreator: mockClientCreator,
	}

	payload := []byte(`{
		"action": "completed",
		"workflow": {
			"name": "unit-tests",
			"path": ".github/workflows/unit-tests.yaml"
		},
		"workflow_run": {
			"id": 123,
			"conclusion": "failure",
			"pull_requests": [
				{
					"number": 1
				}
			]
		},
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"installation": {
			"id": 1
		}
	}`)

	err := handler.Handle(context.Background(), "workflow_run", "deliveryID", payload)
	assert.NoError(t, err)
	assert.True(t, rerunCalled, "Rerun should have been called when workflows list is empty (allows all)")
}

func TestWorkflowRunHandler_Failure_WorkflowInExcludeList(t *testing.T) {
	// Create test server for GitHub API
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	rerunCalled := false

	// Mock PR endpoint
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		pr := &github.PullRequest{
			Number: github.Ptr(1),
			User: &github.User{
				Login: github.Ptr("owner-renovate[bot]"),
			},
			Base: &github.PullRequestBranch{
				Ref: github.Ptr("main"),
			},
		}
		_ = json.NewEncoder(w).Encode(pr)
	})

	// Mock config file endpoint - has exclude-workflows list
	mux.HandleFunc("/repos/owner/repo/contents/.github/ariane-config.yaml", func(w http.ResponseWriter, r *http.Request) {
		configContent := `
rerun:
  max-retries: 3
  exclude-workflows:
    - flaky-test.yaml
    - unstable-e2e.yaml
`
		content := &github.RepositoryContent{
			Content: github.Ptr(configContent),
		}
		_ = json.NewEncoder(w).Encode(content)
	})

	// Mock rerun endpoint (should not be called)
	mux.HandleFunc("/repos/owner/repo/actions/runs/123/rerun-failed-jobs", func(w http.ResponseWriter, r *http.Request) {
		rerunCalled = true
		w.WriteHeader(http.StatusCreated)
	})

	client := github.NewClient(nil)
	baseURL, _ := url.Parse(server.URL + "/")
	client.BaseURL = baseURL

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(1)).Return(client, nil)

	handler := &WorkflowRunHandler{
		ClientCreator: mockClientCreator,
	}

	payload := []byte(`{
		"action": "completed",
		"workflow": {
			"name": "flaky-test",
			"path": ".github/workflows/flaky-test.yaml"
		},
		"workflow_run": {
			"id": 123,
			"conclusion": "failure",
			"pull_requests": [
				{
					"number": 1
				}
			]
		},
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"installation": {
			"id": 1
		}
	}`)

	err := handler.Handle(context.Background(), "workflow_run", "deliveryID", payload)
	assert.NoError(t, err)
	assert.False(t, rerunCalled, "Rerun should not have been called for workflow in exclude list")
}

func TestWorkflowRunHandler_Failure_ExcludeListTakesPrecedenceOverAllowedList(t *testing.T) {
	// Create test server for GitHub API
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	rerunCalled := false

	// Mock PR endpoint
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		pr := &github.PullRequest{
			Number: github.Ptr(1),
			User: &github.User{
				Login: github.Ptr("owner-renovate[bot]"),
			},
			Base: &github.PullRequestBranch{
				Ref: github.Ptr("main"),
			},
		}
		_ = json.NewEncoder(w).Encode(pr)
	})

	// Mock config file endpoint - workflow is in both allowed and exclude lists
	mux.HandleFunc("/repos/owner/repo/contents/.github/ariane-config.yaml", func(w http.ResponseWriter, r *http.Request) {
		configContent := `
rerun:
  max-retries: 3
  workflows:
    - conformance-e2e.yaml
    - integration-test.yaml
  exclude-workflows:
    - integration-test.yaml
`
		content := &github.RepositoryContent{
			Content: github.Ptr(configContent),
		}
		_ = json.NewEncoder(w).Encode(content)
	})

	// Mock rerun endpoint (should not be called because exclude takes precedence)
	mux.HandleFunc("/repos/owner/repo/actions/runs/123/rerun-failed-jobs", func(w http.ResponseWriter, r *http.Request) {
		rerunCalled = true
		w.WriteHeader(http.StatusCreated)
	})

	client := github.NewClient(nil)
	baseURL, _ := url.Parse(server.URL + "/")
	client.BaseURL = baseURL

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(1)).Return(client, nil)

	handler := &WorkflowRunHandler{
		ClientCreator: mockClientCreator,
	}

	payload := []byte(`{
		"action": "completed",
		"workflow": {
			"name": "integration-test",
			"path": ".github/workflows/integration-test.yaml"
		},
		"workflow_run": {
			"id": 123,
			"conclusion": "failure",
			"pull_requests": [
				{
					"number": 1
				}
			]
		},
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"installation": {
			"id": 1
		}
	}`)

	err := handler.Handle(context.Background(), "workflow_run", "deliveryID", payload)
	assert.NoError(t, err)
	assert.False(t, rerunCalled, "Rerun should not have been called because exclude list takes precedence over allowed list")
}

func TestWorkflowRunHandler_Failure_WorkflowNotInExcludeListAllowsRerun(t *testing.T) {
	// Create test server for GitHub API
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	rerunCalled := false

	// Mock PR endpoint
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		pr := &github.PullRequest{
			Number: github.Ptr(1),
			User: &github.User{
				Login: github.Ptr("owner-renovate[bot]"),
			},
			Base: &github.PullRequestBranch{
				Ref: github.Ptr("main"),
			},
		}
		_ = json.NewEncoder(w).Encode(pr)
	})

	// Mock config file endpoint - has exclude list but workflow is not in it
	mux.HandleFunc("/repos/owner/repo/contents/.github/ariane-config.yaml", func(w http.ResponseWriter, r *http.Request) {
		configContent := `
rerun:
  max-retries: 3
  exclude-workflows:
    - flaky-test.yaml
`
		content := &github.RepositoryContent{
			Content: github.Ptr(configContent),
		}
		_ = json.NewEncoder(w).Encode(content)
	})

	// Mock workflow run endpoint - first attempt
	mux.HandleFunc("/repos/owner/repo/actions/runs/123", func(w http.ResponseWriter, r *http.Request) {
		run := &github.WorkflowRun{
			ID:         github.Ptr[int64](123),
			RunAttempt: github.Ptr(1),
		}
		_ = json.NewEncoder(w).Encode(run)
	})

	// Mock jobs endpoint - return failed jobs
	mux.HandleFunc("/repos/owner/repo/actions/runs/123/jobs", func(w http.ResponseWriter, r *http.Request) {
		jobs := &github.Jobs{
			TotalCount: github.Ptr(2),
			Jobs: []*github.WorkflowJob{
				{
					ID:         github.Ptr[int64](1),
					Name:       github.Ptr("test-job-1"),
					Conclusion: github.Ptr("failure"),
				},
			},
		}
		_ = json.NewEncoder(w).Encode(jobs)
	})

	// Mock rerun endpoint (should be called since workflow is not in exclude list)
	mux.HandleFunc("/repos/owner/repo/actions/runs/123/rerun-failed-jobs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			rerunCalled = true
			w.WriteHeader(http.StatusCreated)
		}
	})

	client := github.NewClient(nil)
	baseURL, _ := url.Parse(server.URL + "/")
	client.BaseURL = baseURL

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(1)).Return(client, nil)

	handler := &WorkflowRunHandler{
		ClientCreator: mockClientCreator,
	}

	payload := []byte(`{
		"action": "completed",
		"workflow": {
			"name": "conformance-e2e",
			"path": ".github/workflows/conformance-e2e.yaml"
		},
		"workflow_run": {
			"id": 123,
			"conclusion": "failure",
			"pull_requests": [
				{
					"number": 1
				}
			]
		},
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"installation": {
			"id": 1
		}
	}`)

	err := handler.Handle(context.Background(), "workflow_run", "deliveryID", payload)
	assert.NoError(t, err)
	assert.True(t, rerunCalled, "Rerun should have been called for workflow not in exclude list")
}
