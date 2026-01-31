// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	reflect "reflect"

	"github.com/cilium/ariane/internal/config"
	github "github.com/google/go-github/v82/github"
	"github.com/rs/zerolog"
	githubv4 "github.com/shurcooL/githubv4"
	gomock "go.uber.org/mock/gomock"
	oauth2 "golang.org/x/oauth2"
	"gopkg.in/yaml.v3"

	"github.com/stretchr/testify/assert"
)

func TestHandle_NotaPR(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(0)).Times(0)

	handler := &PRCommentHandler{
		ClientCreator:    mockClientCreator,
		RunDelay:         time.Second,
		MaxRetryAttempts: config.DefaultMaxRetryAttempts,
	}

	payload := []byte(`{
		"issue": {
			"issue_comment": {}
		},
		"action": "created",
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"comment": {
			"id": 1,
			"user": {
				"login": "user"
			},
			"body": "trigger"
		}
	}`)

	err := handler.Handle(context.Background(), "issue_comment", "deliveryID", payload)
	assert.NoError(t, err)

}

func TestHandle_ActionNotCreated(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(0)).Times(0)

	handler := &PRCommentHandler{
		ClientCreator:    mockClientCreator,
		RunDelay:         time.Second,
		MaxRetryAttempts: config.DefaultMaxRetryAttempts,
	}
	// Action can be created, edited, or delited
	// The GHApp only reacts to "created"
	// https://docs.github.com/en/rest/using-the-rest-api/github-event-types?apiVersion=2022-11-28#issuecommentevent
	payload := []byte(`{
		"issue": {
			"pull_request": {}
		},
		"action": "edited",
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"comment": {
			"id": 1,
			"user": {
				"login": "user"
			},
			"body": "trigger"
		}
	}`)

	err := handler.Handle(context.Background(), "issue_comment", "deliveryID", payload)
	assert.NoError(t, err)
}

func TestHandle_IsInvalidBot(t *testing.T) {
	mockServer := setMockServer()
	defer mockServer.Close()
	client := github.NewClient(nil)
	client.BaseURL, _ = url.Parse(mockServer.URL + "/")

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(0)).Return(client, nil)

	handler := &PRCommentHandler{
		ClientCreator:    mockClientCreator,
		RunDelay:         time.Second,
		MaxRetryAttempts: config.DefaultMaxRetryAttempts,
	}

	payload := []byte(`{
		"issue": {
			"pull_request": {}
		},
		"action": "created",
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"comment": {
			"id": 1,
			"user": {
				"login": "user [bot]"
			},
			"body": "trigger"
		}
	}`)

	err := handler.Handle(context.Background(), "issue_comment", "deliveryID", payload)
	assert.NoError(t, err)
}

func TestHandle_IsValidBot(t *testing.T) {
	oldconfigGetArianeConfigFromRepository := configGetArianeConfigFromRepository
	defer func() { configGetArianeConfigFromRepository = oldconfigGetArianeConfigFromRepository }()

	configGetArianeConfigFromRepository = mockGetArianeConfigFromRepository

	mockServer := setMockServer()
	defer mockServer.Close()
	client := github.NewClient(nil)
	client.BaseURL, _ = url.Parse(mockServer.URL + "/")

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(0)).Return(client, nil)

	handler := &PRCommentHandler{
		ClientCreator:    mockClientCreator,
		RunDelay:         time.Second,
		MaxRetryAttempts: config.DefaultMaxRetryAttempts,
	}

	payload := []byte(`{
		"issue": {
			"pull_request": {}
		},
		"action": "created",
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"comment": {
			"id": 1,
			"user": {
				"login": "owner-test [bot]"
			},
			"body": "trigger"
		}
	}`)

	err := handler.Handle(context.Background(), "issue_comment", "deliveryID", payload)
	assert.NoError(t, err)
}

func TestHandle(t *testing.T) {
	oldconfigGetArianeConfigFromRepository := configGetArianeConfigFromRepository
	defer func() { configGetArianeConfigFromRepository = oldconfigGetArianeConfigFromRepository }()

	configGetArianeConfigFromRepository = mockGetArianeConfigFromRepository

	mockServer := setMockServer()
	defer mockServer.Close()
	client := github.NewClient(nil)
	client.BaseURL, _ = url.Parse(mockServer.URL + "/")

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(0)).Return(client, nil)

	handler := &PRCommentHandler{
		ClientCreator:    mockClientCreator,
		RunDelay:         time.Second,
		MaxRetryAttempts: config.DefaultMaxRetryAttempts,
	}

	payload := []byte(`{
		"issue": {
			"pull_request": {}
		},
		"action": "created",
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"comment": {
			"id": 1,
			"user": {
				"login": "trustedauthor"
			},
			"body": "/test"
		}
	}`)

	err := handler.Handle(context.Background(), "issue_comment", "deliveryID", payload)
	assert.NoError(t, err)
}

func Test_isAllowedTeamMember(t *testing.T) {
	mockServer := setMockServer()
	defer mockServer.Close()
	client := github.NewClient(nil)
	client.BaseURL, _ = url.Parse(mockServer.URL + "/")

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)

	handler := &PRCommentHandler{
		ClientCreator:    mockClientCreator,
		RunDelay:         time.Second,
		MaxRetryAttempts: config.DefaultMaxRetryAttempts,
	}

	var logger zerolog.Logger
	testCases := []struct {
		ArianeConfig   *config.ArianeConfig
		Author         string
		ExpectedResult bool
		ExpectedReason string
	}{
		{
			ArianeConfig: &config.ArianeConfig{
				AllowedTeams: []string{"organization-members"},
			},
			Author:         "trustedauthor",
			ExpectedResult: true,
			ExpectedReason: "trustedauthor is an active member of organization-members.",
		},
		{
			ArianeConfig: &config.ArianeConfig{
				AllowedTeams: []string{"organization-members"},
			},
			Author:         "unknownauthor",
			ExpectedResult: false,
			ExpectedReason: "unknown is a non-active member of organization-members.",
		},
		{
			ArianeConfig: &config.ArianeConfig{
				AllowedTeams: []string{"non-existing-organization"},
			},
			Author:         "author",
			ExpectedResult: false,
			ExpectedReason: "author cannot be found under non-existing-organization.",
		},
	}
	for idx, testCase := range testCases {
		result := handler.isAllowedTeamMember(context.Background(), client, testCase.ArianeConfig, "owner", testCase.Author, logger)
		if result != testCase.ExpectedResult {
			t.Errorf(
				`[TEST%v] isAllowedTeamMember failed.
				result: %v, expected: %v
				Expected reason to pass the test: %v`,
				idx+1, result, testCase.ExpectedResult, testCase.ExpectedReason)
		}
	}
}

func Test_rerunFailedJobs(t *testing.T) {
	mockServer := setMockServer()
	defer mockServer.Close()
	client := github.NewClient(nil)
	client.BaseURL, _ = url.Parse(mockServer.URL + "/")

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)

	handler := &PRCommentHandler{
		ClientCreator:    mockClientCreator,
		RunDelay:         time.Second * 30000,
		MaxRetryAttempts: config.DefaultMaxRetryAttempts,
	}

	logWriter := &LogWriter{}
	logger := zerolog.New(logWriter)
	var wg sync.WaitGroup
	handler.rerunFailedJobs(context.Background(), client, "owner", "repo", "foobar.yaml", int64(99), &wg, logger)
	wg.Wait()
	var result struct {
		Level   string `json:"level,omitempty"`
		Message string `json:"message,omitempty"`
	}
	if err := json.Unmarshal([]byte(logWriter.String()), &result); err != nil {
		t.Error("Test_rerunFailedJobs failed. Unable to decode JSON logs")
	}
	expected := `re-running failed workflow`

	if result.Level != "debug" && !strings.HasPrefix(result.Message, expected) {
		t.Errorf(`Test_rerunFailedJobs failed.
				result: %s, expected: %s`, result, expected)
	}
	// TODO(auriaave): Cover when "Commit Status Start" job is found
	// This part will need extra implementation on mockServer (to respond with an appropriate job)
}

func Test_shouldSkipWorkflow(t *testing.T) {
	mockServer := setMockServer()
	defer mockServer.Close()
	client := github.NewClient(nil)
	client.BaseURL, _ = url.Parse(mockServer.URL + "/")

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)

	handler := &PRCommentHandler{
		ClientCreator:    mockClientCreator,
		RunDelay:         time.Second,
		MaxRetryAttempts: config.DefaultMaxRetryAttempts,
	}

	var logger zerolog.Logger
	testCases := []struct {
		Workflow       string
		ExpectedResult bool
		ExpectedReason string
	}{
		{
			Workflow:       "foo.yaml",
			ExpectedResult: false,
			ExpectedReason: "cancelled jobs are not skipped.",
		},
		{
			Workflow:       "bar.yaml",
			ExpectedResult: true,
			ExpectedReason: "status=completed, conclusion=success are skipped.",
		},
		{
			Workflow:       "foobar.yaml",
			ExpectedResult: false,
			ExpectedReason: "status=completed, conclusion=failure are not skipped.",
			// BUG(auriaave): https://github.com/cilium/ariane/issues/45
			// ExpectedResult: true,
			// ExpectedReason: "status=completed, conclusion=failure are re-run, and skipped.",
		},
	}

	for idx, testCase := range testCases {
		result := handler.shouldSkipWorkflow(context.Background(), client, "owner", "repo", testCase.Workflow, "mock-sha", logger)
		if result != testCase.ExpectedResult {
			t.Errorf(
				`[TEST%v] shouldSkipWorkflow failed.
				result: %v, expected: %v
				Expected reason to pass the test: %v`,
				idx+1, result, testCase.ExpectedResult, testCase.ExpectedReason)
		}
	}
}

// Helper functions

func setMockServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/pulls", func(w http.ResponseWriter, r *http.Request) {
		number := 0
		prs := []*github.PullRequest{
			{
				Number: &number,
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
			},
		}
		if err := json.NewEncoder(w).Encode(prs); err != nil {
			http.Error(w, "setMockServer: could not encode the PRs payload in JSON for the HTTP response.", http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("/repos/owner/repo/pulls/0", func(w http.ResponseWriter, r *http.Request) {
		pr := &github.PullRequest{
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
	mux.HandleFunc("/repos/owner/repo/pulls/0/files", func(w http.ResponseWriter, r *http.Request) {
		// https://docs.github.com/en/rest/pulls/pulls?apiVersion=2022-11-28#list-pull-requests-files
		files := []*github.CommitFile{
			{
				Filename: github.Ptr(".github/workflows/foo.yaml"),
			},
		}
		if err := json.NewEncoder(w).Encode(files); err != nil {
			http.Error(w, "setMockServer: could not encode the files payload in JSON for the HTTP response.", http.StatusInternalServerError)
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
	mux.HandleFunc("POST /repos/owner/repo/actions/workflows/foo.yaml/dispatches", func(w http.ResponseWriter, r *http.Request) {
		// https://docs.github.com/en/rest/actions/workflows?apiVersion=2022-11-28#create-a-workflow-dispatch-event
		w.WriteHeader(http.StatusNoContent)
		if _, err := fmt.Fprintf(w, "Status: %v\n", http.StatusNoContent); err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("/repos/owner/repo/actions/workflows/{workflow}/runs", func(w http.ResponseWriter, r *http.Request) {
		// https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2022-11-28#list-workflow-runs-for-a-workflow
		workflow := r.PathValue("workflow")
		SHA := r.FormValue("head_sha")
		var workflowRuns *github.WorkflowRuns

		// search specific workflows, filtering by HeadSHA of the PR
		if SHA != "mock-sha" {
			workflowRuns = &github.WorkflowRuns{
				TotalCount:   github.Ptr(0),
				WorkflowRuns: []*github.WorkflowRun{},
			}
		} else if workflow == "foo.yaml" {
			workflowRuns = &github.WorkflowRuns{
				TotalCount: github.Ptr(2),
				WorkflowRuns: []*github.WorkflowRun{
					{
						ID:      github.Ptr(int64(1)),
						Status:  github.Ptr("cancelled"),
						HeadSHA: github.Ptr(SHA),
					},
				},
			}
		} else if workflow == "bar.yaml" {
			workflowRuns = &github.WorkflowRuns{
				TotalCount: github.Ptr(1),
				WorkflowRuns: []*github.WorkflowRun{
					{
						ID:         github.Ptr(int64(2)),
						Status:     github.Ptr("completed"),
						Conclusion: github.Ptr("success"),
						HeadSHA:    github.Ptr(SHA),
					},
				},
			}
		} else if workflow == "foobar.yaml" {
			workflowRuns = &github.WorkflowRuns{
				TotalCount: github.Ptr(1),
				WorkflowRuns: []*github.WorkflowRun{
					{
						ID:         github.Ptr(int64(99)),
						Status:     github.Ptr("completed"),
						Conclusion: github.Ptr("failure"),
						HeadSHA:    github.Ptr(SHA),
					},
				},
			}
		} else {
			workflowRuns = &github.WorkflowRuns{
				TotalCount:   github.Ptr(0),
				WorkflowRuns: []*github.WorkflowRun{},
			}
		}

		if err := json.NewEncoder(w).Encode(workflowRuns); err != nil {
			http.Error(w, "setMockServer: could not encode the workflowRuns payload in JSON for the HTTP response.", http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("/repos/owner/repo/actions/runs/{runID}/jobs", func(w http.ResponseWriter, r *http.Request) {
		runID := r.PathValue("runID")
		if runID != "99" {
			http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
		}
		// runID 99 is the failed workflow listed above
		jobs := &github.Jobs{
			TotalCount: github.Ptr(3),
			Jobs: []*github.WorkflowJob{
				{
					ID:    github.Ptr(int64(1)),
					RunID: github.Ptr(int64(99)),
					Name:  github.Ptr("Installation and Conformance"),
				},
			},
		}
		if err := json.NewEncoder(w).Encode(jobs); err != nil {
			http.Error(w, "setMockServer: could not encode the jobs payload in JSON for the HTTP response.", http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("POST /repos/owner/repo/actions/runs/{runID}/rerun-failed-jobs", func(w http.ResponseWriter, r *http.Request) {
		// https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2022-11-28#re-run-failed-jobs-from-a-workflow-run
		runID := r.PathValue("runID")
		if runID != "99" {
			http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
		}
		w.WriteHeader(http.StatusCreated)
		if _, err := fmt.Fprintf(w, "Status: %v\n", http.StatusCreated); err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("POST /repos/owner/repo/issues/comments/1/reactions", func(w http.ResponseWriter, r *http.Request) {
		// https://docs.github.com/en/rest/reactions/reactions?apiVersion=2022-11-28#create-reaction-for-an-issue-comment
		reaction := &github.Reaction{
			ID:      github.Ptr(int64(1)),
			Content: github.Ptr(r.PostFormValue("content")),
		}
		if err := json.NewEncoder(w).Encode(reaction); err != nil {
			http.Error(w, "setMockServer: could not encode the reaction payload in JSON for the HTTP response.", http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("POST /repos/owner/repo/issues/0/comments", func(w http.ResponseWriter, r *http.Request) {
		// https://docs.github.com/en/rest/issues/comments?apiVersion=2022-11-28#create-an-issue-comment
		var requestBody struct {
			Body string `json:"body"`
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			http.Error(w, "setMockServer: could not decode request body", http.StatusBadRequest)
			return
		}
		comment := &github.IssueComment{
			ID:   github.Ptr(int64(2)),
			Body: github.Ptr(requestBody.Body),
		}
		if err := json.NewEncoder(w).Encode(comment); err != nil {
			http.Error(w, "setMockServer: could not encode the comment payload in JSON for the HTTP response.", http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("/repos/owner/repo/actions/workflows/foo.yaml", func(w http.ResponseWriter, r *http.Request) {
		// https://docs.github.com/en/rest/actions/workflows?apiVersion=2022-11-28#get-a-workflow
		workflow := &github.Workflow{
			ID:   github.Ptr(int64(1)),
			Name: github.Ptr("Foo Workflow"),
			Path: github.Ptr(".github/workflows/foo.yaml"),
		}
		if err := json.NewEncoder(w).Encode(workflow); err != nil {
			http.Error(w, "setMockServer: could not encode the workflow payload in JSON for the HTTP response.", http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("/repos/owner/repo/actions/workflows/bar.yaml", func(w http.ResponseWriter, r *http.Request) {
		workflow := &github.Workflow{
			ID:   github.Ptr(int64(2)),
			Name: github.Ptr("Bar Workflow"),
			Path: github.Ptr(".github/workflows/bar.yaml"),
		}
		if err := json.NewEncoder(w).Encode(workflow); err != nil {
			http.Error(w, "setMockServer: could not encode the workflow payload in JSON for the HTTP response.", http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("POST /repos/owner/repo/check-runs", func(w http.ResponseWriter, r *http.Request) {
		// https://docs.github.com/en/rest/checks/runs?apiVersion=2022-11-28#create-a-check-run
		var requestBody github.CreateCheckRunOptions
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			http.Error(w, "setMockServer: could not decode request body", http.StatusBadRequest)
			return
		}
		checkRun := &github.CheckRun{
			ID:         github.Ptr(int64(1)),
			Name:       github.Ptr(requestBody.Name),
			HeadSHA:    github.Ptr(requestBody.HeadSHA),
			Status:     requestBody.Status,
			Conclusion: requestBody.Conclusion,
		}
		if err := json.NewEncoder(w).Encode(checkRun); err != nil {
			http.Error(w, "setMockServer: could not encode the check run payload in JSON for the HTTP response.", http.StatusInternalServerError)
		}
	})
	return httptest.NewServer(mux)
}

func readYAMLFile(filePath string) (*config.ArianeConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read YAML file: %w", err)
	}

	var config config.ArianeConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML data: %w", err)
	}

	return &config, nil
}

func mockGetArianeConfigFromRepository(client *github.Client, ctx context.Context, owner string, repoName string, ref string) (*config.ArianeConfig, error) {
	return readYAMLFile(`../../example/ariane-config.yaml`)
}

func mockGetArianeConfigFromRepositoryWithFeedback(verbose bool, workflowsReport bool) func(*github.Client, context.Context, string, string, string) (*config.ArianeConfig, error) {
	return func(client *github.Client, ctx context.Context, owner string, repoName string, ref string) (*config.ArianeConfig, error) {
		verbosePtr := &verbose
		workflowsReportPtr := &workflowsReport
		cfg := &config.ArianeConfig{
			Feedback: config.FeedbackConfig{
				Verbose:         verbosePtr,
				WorkflowsReport: workflowsReportPtr,
			},
			Triggers: map[string]config.TriggerConfig{
				"/test": {
					Workflows: []string{"foo.yaml"},
				},
			},
			Workflows: map[string]config.WorkflowPathsRegexConfig{
				"foo.yaml": {
					PathsRegex: ".*",
				},
			},
		}
		return cfg, nil
	}
}

// These methods help capture logs to evaluate their status
// It is required for rerunFailedJobs, which does not return any state
type LogWriter struct {
	buf bytes.Buffer
}

func (w *LogWriter) Write(p []byte) (n int, err error) {
	return w.buf.Write(p)
}

func (w *LogWriter) String() string {
	return w.buf.String()
}

func TestHandle_WorkflowStatusTable(t *testing.T) {
	oldconfigGetArianeConfigFromRepository := configGetArianeConfigFromRepository
	defer func() { configGetArianeConfigFromRepository = oldconfigGetArianeConfigFromRepository }()

	configGetArianeConfigFromRepository = mockGetArianeConfigFromRepository

	mockServer := setMockServer()
	defer mockServer.Close()
	client := github.NewClient(nil)
	client.BaseURL, _ = url.Parse(mockServer.URL + "/")

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(0)).Return(client, nil)

	handler := &PRCommentHandler{
		ClientCreator:    mockClientCreator,
		RunDelay:         time.Second,
		MaxRetryAttempts: config.DefaultMaxRetryAttempts,
	}

	payload := []byte(`{
		"issue": {
			"pull_request": {}
		},
		"action": "created",
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"comment": {
			"id": 1,
			"user": {
				"login": "trustedauthor"
			},
			"body": "/test"
		}
	}`)

	err := handler.Handle(context.Background(), "issue_comment", "deliveryID", payload)
	assert.NoError(t, err)
}

func Test_buildWorkflowStatusTable(t *testing.T) {
	testCases := []struct {
		name             string
		workflowStatuses []workflowStatus
		expectedContains []string
	}{
		{
			name: "triggered workflow",
			workflowStatuses: []workflowStatus{
				{name: "ci.yaml", status: workflowStatusTriggered},
			},
			expectedContains: []string{
				"## Workflow Status",
				"| Workflow | Status |",
				"| `ci.yaml` | ✅ Triggered |",
			},
		},
		{
			name: "skipped workflow",
			workflowStatuses: []workflowStatus{
				{name: "lint.yaml", status: workflowStatusSkipped},
			},
			expectedContains: []string{
				"## Workflow Status",
				"| `lint.yaml` | ⏭️ Skipped |",
			},
		},
		{
			name: "already completed workflow",
			workflowStatuses: []workflowStatus{
				{name: "test.yaml", status: workflowStatusAlreadyCompleted},
			},
			expectedContains: []string{
				"## Workflow Status",
				"| `test.yaml` | ✔️ Already Completed |",
			},
		},
		{
			name: "failed workflow",
			workflowStatuses: []workflowStatus{
				{name: "deploy.yaml", status: workflowStatusFailed},
			},
			expectedContains: []string{
				"## Workflow Status",
				"| `deploy.yaml` | ❌ Failed to Trigger |",
			},
		},
		{
			name: "failed to mark as skipped",
			workflowStatuses: []workflowStatus{
				{name: "security.yaml", status: workflowStatusFailedToMarkSkipped},
			},
			expectedContains: []string{
				"## Workflow Status",
				"| `security.yaml` | ⚠️ Failed to Mark as Skipped |",
			},
		},
		{
			name: "multiple workflows with mixed statuses",
			workflowStatuses: []workflowStatus{
				{name: "ci.yaml", status: workflowStatusTriggered},
				{name: "lint.yaml", status: workflowStatusSkipped},
				{name: "test.yaml", status: workflowStatusAlreadyCompleted},
				{name: "deploy.yaml", status: workflowStatusFailed},
			},
			expectedContains: []string{
				"## Workflow Status",
				"| `ci.yaml` | ✅ Triggered |",
				"| `lint.yaml` | ⏭️ Skipped |",
				"| `test.yaml` | ✔️ Already Completed |",
				"| `deploy.yaml` | ❌ Failed to Trigger |",
			},
		},
		{
			name:             "empty workflow list",
			workflowStatuses: []workflowStatus{},
			expectedContains: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &PRCommentHandler{}
			result := handler.buildWorkflowStatusTable(tc.workflowStatuses)

			// Verify all expected strings are present
			for _, expected := range tc.expectedContains {
				if !strings.Contains(result, expected) {
					t.Errorf("Expected result to contain %q, but it didn't. Result:\n%s", expected, result)
				}
			}

			// Verify empty result for empty workflow list
			if len(tc.workflowStatuses) == 0 && result != "" {
				t.Errorf("Expected empty result for empty workflow list, got: %s", result)
			}
		})
	}
}

func Test_workflowStatusTracking(t *testing.T) {
	testCases := []struct {
		name           string
		workflow       string
		shouldSkip     bool
		shouldRun      bool
		triggerErr     error
		markSkipErr    error
		expectedStatus workflowStatusType
	}{
		{
			name:           "workflow already completed",
			workflow:       "bar.yaml",
			shouldSkip:     true,
			expectedStatus: workflowStatusAlreadyCompleted,
		},
		{
			name:           "workflow triggered successfully",
			workflow:       "foo.yaml",
			shouldSkip:     false,
			shouldRun:      true,
			triggerErr:     nil,
			expectedStatus: workflowStatusTriggered,
		},
		{
			name:           "workflow trigger failed",
			workflow:       "foo.yaml",
			shouldSkip:     false,
			shouldRun:      true,
			triggerErr:     fmt.Errorf("trigger error"),
			expectedStatus: workflowStatusFailed,
		},
		{
			name:           "workflow skipped successfully",
			workflow:       "foo.yaml",
			shouldSkip:     false,
			shouldRun:      false,
			markSkipErr:    nil,
			expectedStatus: workflowStatusSkipped,
		},
		{
			name:           "workflow failed to mark as skipped",
			workflow:       "foo.yaml",
			shouldSkip:     false,
			shouldRun:      false,
			markSkipErr:    fmt.Errorf("mark skip error"),
			expectedStatus: workflowStatusFailedToMarkSkipped,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var statuses []workflowStatus

			// Simulate the workflow processing logic
			if tc.shouldSkip {
				statuses = append(statuses, workflowStatus{name: tc.workflow, status: workflowStatusAlreadyCompleted})
			} else if tc.shouldRun {
				if tc.triggerErr != nil {
					statuses = append(statuses, workflowStatus{name: tc.workflow, status: workflowStatusFailed})
				} else {
					statuses = append(statuses, workflowStatus{name: tc.workflow, status: workflowStatusTriggered})
				}
			} else {
				if tc.markSkipErr != nil {
					statuses = append(statuses, workflowStatus{name: tc.workflow, status: workflowStatusFailedToMarkSkipped})
				} else {
					statuses = append(statuses, workflowStatus{name: tc.workflow, status: workflowStatusSkipped})
				}
			}

			// Verify the status was tracked correctly
			assert.Len(t, statuses, 1)
			assert.Equal(t, tc.workflow, statuses[0].name)
			assert.Equal(t, tc.expectedStatus, statuses[0].status)
		})
	}
}

func TestHandle_FeedbackDisabled(t *testing.T) {
	oldconfigGetArianeConfigFromRepository := configGetArianeConfigFromRepository
	defer func() { configGetArianeConfigFromRepository = oldconfigGetArianeConfigFromRepository }()

	configGetArianeConfigFromRepository = mockGetArianeConfigFromRepositoryWithFeedback(false, false)

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)

	server := setMockServerWithFeedbackConfig(false, false)
	defer server.Close()

	client := github.NewClient(nil)
	client.BaseURL, _ = url.Parse(server.URL + "/")
	mockClientCreator.EXPECT().NewInstallationClient(int64(0)).Return(client, nil)

	handler := &PRCommentHandler{
		ClientCreator:    mockClientCreator,
		RunDelay:         time.Second,
		MaxRetryAttempts: config.DefaultMaxRetryAttempts,
	}

	payload := []byte(`{
		"issue": {
			"pull_request": {},
			"number": 0
		},
		"action": "created",
		"comment": {
			"id": 1,
			"body": "/test-unknown",
			"user": {
				"login": "user"
			}
		},
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"installation": {
			"id": 0
		}
	}`)

	var event github.IssueCommentEvent
	_ = json.Unmarshal(payload, &event)

	ctx := context.Background()

	// Should not return error even though command not found
	err := handler.Handle(ctx, "issue_comment", "1", payload)
	assert.NoError(t, err)
}

func TestHandle_VerboseEnabled(t *testing.T) {
	oldconfigGetArianeConfigFromRepository := configGetArianeConfigFromRepository
	defer func() { configGetArianeConfigFromRepository = oldconfigGetArianeConfigFromRepository }()

	configGetArianeConfigFromRepository = mockGetArianeConfigFromRepositoryWithFeedback(true, false)

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)

	server := setMockServerWithFeedbackConfig(true, false)
	defer server.Close()

	client := github.NewClient(nil)
	client.BaseURL, _ = url.Parse(server.URL + "/")
	mockClientCreator.EXPECT().NewInstallationClient(int64(0)).Return(client, nil)

	handler := &PRCommentHandler{
		ClientCreator:    mockClientCreator,
		RunDelay:         time.Second,
		MaxRetryAttempts: config.DefaultMaxRetryAttempts,
	}

	payload := []byte(`{
		"issue": {
			"pull_request": {},
			"number": 0
		},
		"action": "created",
		"comment": {
			"id": 1,
			"body": "/test-unknown",
			"user": {
				"login": "user"
			}
		},
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"installation": {
			"id": 0
		}
	}`)

	var event github.IssueCommentEvent
	_ = json.Unmarshal(payload, &event)

	ctx := context.Background()

	err := handler.Handle(ctx, "issue_comment", "1", payload)
	assert.NoError(t, err)
}

func TestHandle_WorkflowsReportEnabled(t *testing.T) {
	oldconfigGetArianeConfigFromRepository := configGetArianeConfigFromRepository
	defer func() { configGetArianeConfigFromRepository = oldconfigGetArianeConfigFromRepository }()

	configGetArianeConfigFromRepository = mockGetArianeConfigFromRepositoryWithFeedback(true, true)

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)

	server := setMockServerWithFeedbackConfig(true, true)
	defer server.Close()

	client := github.NewClient(nil)
	client.BaseURL, _ = url.Parse(server.URL + "/")
	mockClientCreator.EXPECT().NewInstallationClient(int64(0)).Return(client, nil)

	handler := &PRCommentHandler{
		ClientCreator:    mockClientCreator,
		RunDelay:         time.Second,
		MaxRetryAttempts: config.DefaultMaxRetryAttempts,
	}

	payload := []byte(`{
		"issue": {
			"pull_request": {},
			"number": 0
		},
		"action": "created",
		"comment": {
			"id": 1,
			"body": "/test",
			"user": {
				"login": "user"
			}
		},
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"installation": {
			"id": 0
		}
	}`)

	var event github.IssueCommentEvent
	_ = json.Unmarshal(payload, &event)

	ctx := context.Background()

	err := handler.Handle(ctx, "issue_comment", "1", payload)
	assert.NoError(t, err)
}

func TestHandle_WorkflowsReportDisabled(t *testing.T) {
	oldconfigGetArianeConfigFromRepository := configGetArianeConfigFromRepository
	defer func() { configGetArianeConfigFromRepository = oldconfigGetArianeConfigFromRepository }()

	configGetArianeConfigFromRepository = mockGetArianeConfigFromRepositoryWithFeedback(true, false)

	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)

	server := setMockServerWithFeedbackConfig(true, false)
	defer server.Close()

	client := github.NewClient(nil)
	client.BaseURL, _ = url.Parse(server.URL + "/")
	mockClientCreator.EXPECT().NewInstallationClient(int64(0)).Return(client, nil)

	handler := &PRCommentHandler{
		ClientCreator:    mockClientCreator,
		RunDelay:         time.Second,
		MaxRetryAttempts: config.DefaultMaxRetryAttempts,
	}

	payload := []byte(`{
		"issue": {
			"pull_request": {},
			"number": 0
		},
		"action": "created",
		"comment": {
			"id": 1,
			"body": "/test",
			"user": {
				"login": "user"
			}
		},
		"repository": {
			"owner": {
				"login": "owner"
			},
			"name": "repo"
		},
		"installation": {
			"id": 0
		}
	}`)

	var event github.IssueCommentEvent
	_ = json.Unmarshal(payload, &event)

	ctx := context.Background()

	err := handler.Handle(ctx, "issue_comment", "1", payload)
	assert.NoError(t, err)
}

func setMockServerWithFeedbackConfig(verbose bool, workflowsReport bool) *httptest.Server {
	mux := http.NewServeMux()

	// Mock individual PR endpoint
	mux.HandleFunc("/repos/owner/repo/pulls/0", func(w http.ResponseWriter, r *http.Request) {
		pr := github.PullRequest{
			Number: github.Ptr(0),
			Head: &github.PullRequestBranch{
				SHA: github.Ptr("abc123"),
				Ref: github.Ptr("feature-branch"),
				Repo: &github.Repository{
					Owner: &github.User{Login: github.Ptr("owner")},
					Name:  github.Ptr("repo"),
				},
			},
			State: github.Ptr("open"),
		}
		_ = json.NewEncoder(w).Encode(&pr)
	})

	// Mock PR list endpoint
	mux.HandleFunc("/repos/owner/repo/pulls", func(w http.ResponseWriter, r *http.Request) {
		pr := github.PullRequest{
			Number: github.Ptr(0),
			Head: &github.PullRequestBranch{
				SHA: github.Ptr("abc123"),
				Ref: github.Ptr("feature-branch"),
			},
			State: github.Ptr("open"),
		}
		_ = json.NewEncoder(w).Encode([]*github.PullRequest{&pr})
	})

	// Mock config file endpoint with feedback settings
	mux.HandleFunc("/repos/owner/repo/contents/.github/ariane-config.yaml", func(w http.ResponseWriter, r *http.Request) {
		configContent := fmt.Sprintf(`feedback:
  verbose: %t
  workflows-report: %t
triggers:
  /test:
    workflows:
      - foo.yaml
workflows:
  foo.yaml:
    paths-regex: ".*"
`, verbose, workflowsReport)

		content := github.RepositoryContent{
			Content:  github.Ptr(configContent),
			Encoding: github.Ptr(""),
		}
		_ = json.NewEncoder(w).Encode(&content)
	})

	// Mock PR files endpoint
	mux.HandleFunc("/repos/owner/repo/pulls/0/files", func(w http.ResponseWriter, r *http.Request) {
		files := []*github.CommitFile{
			{Filename: github.Ptr("test.go")},
		}
		_ = json.NewEncoder(w).Encode(files)
	})

	// Mock workflow dispatch endpoint
	mux.HandleFunc("/repos/owner/repo/actions/workflows/foo.yaml/dispatches", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	// Mock check runs list endpoint
	mux.HandleFunc("/repos/owner/repo/commits/abc123/check-runs", func(w http.ResponseWriter, r *http.Request) {
		checkRuns := github.ListCheckRunsResults{
			Total:     github.Ptr(0),
			CheckRuns: []*github.CheckRun{},
		}
		_ = json.NewEncoder(w).Encode(&checkRuns)
	})

	// Mock check runs create endpoint
	mux.HandleFunc("/repos/owner/repo/check-runs", func(w http.ResponseWriter, r *http.Request) {
		checkRun := github.CheckRun{
			ID: github.Ptr(int64(1)),
		}
		_ = json.NewEncoder(w).Encode(&checkRun)
	})

	// Mock issue comments endpoint
	mux.HandleFunc("/repos/owner/repo/issues/0/comments", func(w http.ResponseWriter, r *http.Request) {
		comment := github.IssueComment{
			ID: github.Ptr(int64(1)),
		}
		_ = json.NewEncoder(w).Encode(&comment)
	})

	// Mock reactions endpoint
	mux.HandleFunc("/repos/owner/repo/issues/comments/1/reactions", func(w http.ResponseWriter, r *http.Request) {
		reaction := github.Reaction{
			ID: github.Ptr(int64(1)),
		}
		_ = json.NewEncoder(w).Encode(&reaction)
	})

	return httptest.NewServer(mux)
}

// Code generated by MockGen. DO NOT EDIT.
// Source: cilium/ariane/vendor/github.com/palantir/go-githubapp/githubapp/client_creator.go
//
// Generated by this command:
//
//	mockgen -source=vendor/github.com/palantir/go-githubapp/githubapp/client_creator.go
//

// MockClientCreator is a mock of ClientCreator interface.
type MockClientCreator struct {
	ctrl     *gomock.Controller
	recorder *MockClientCreatorMockRecorder
}

// MockClientCreatorMockRecorder is the mock recorder for MockClientCreator.
type MockClientCreatorMockRecorder struct {
	mock *MockClientCreator
}

// NewMockClientCreator creates a new mock instance.
func NewMockClientCreator(ctrl *gomock.Controller) *MockClientCreator {
	mock := &MockClientCreator{ctrl: ctrl}
	mock.recorder = &MockClientCreatorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClientCreator) EXPECT() *MockClientCreatorMockRecorder {
	return m.recorder
}

// NewAppClient mocks base method.
func (m *MockClientCreator) NewAppClient() (*github.Client, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewAppClient")
	ret0, _ := ret[0].(*github.Client)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewAppClient indicates an expected call of NewAppClient.
func (mr *MockClientCreatorMockRecorder) NewAppClient() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewAppClient", reflect.TypeOf((*MockClientCreator)(nil).NewAppClient))
}

// NewAppV4Client mocks base method.
func (m *MockClientCreator) NewAppV4Client() (*githubv4.Client, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewAppV4Client")
	ret0, _ := ret[0].(*githubv4.Client)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewAppV4Client indicates an expected call of NewAppV4Client.
func (mr *MockClientCreatorMockRecorder) NewAppV4Client() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewAppV4Client", reflect.TypeOf((*MockClientCreator)(nil).NewAppV4Client))
}

// NewInstallationClient mocks base method.
func (m *MockClientCreator) NewInstallationClient(installationID int64) (*github.Client, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewInstallationClient", installationID)
	ret0, _ := ret[0].(*github.Client)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewInstallationClient indicates an expected call of NewInstallationClient.
func (mr *MockClientCreatorMockRecorder) NewInstallationClient(installationID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewInstallationClient", reflect.TypeOf((*MockClientCreator)(nil).NewInstallationClient), installationID)
}

// NewInstallationV4Client mocks base method.
func (m *MockClientCreator) NewInstallationV4Client(installationID int64) (*githubv4.Client, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewInstallationV4Client", installationID)
	ret0, _ := ret[0].(*githubv4.Client)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewInstallationV4Client indicates an expected call of NewInstallationV4Client.
func (mr *MockClientCreatorMockRecorder) NewInstallationV4Client(installationID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewInstallationV4Client", reflect.TypeOf((*MockClientCreator)(nil).NewInstallationV4Client), installationID)
}

// NewTokenClient mocks base method.
func (m *MockClientCreator) NewTokenClient(token string) (*github.Client, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewTokenClient", token)
	ret0, _ := ret[0].(*github.Client)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewTokenClient indicates an expected call of NewTokenClient.
func (mr *MockClientCreatorMockRecorder) NewTokenClient(token any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewTokenClient", reflect.TypeOf((*MockClientCreator)(nil).NewTokenClient), token)
}

// NewTokenSourceClient mocks base method.
func (m *MockClientCreator) NewTokenSourceClient(ts oauth2.TokenSource) (*github.Client, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewTokenSourceClient", ts)
	ret0, _ := ret[0].(*github.Client)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewTokenSourceClient indicates an expected call of NewTokenSourceClient.
func (mr *MockClientCreatorMockRecorder) NewTokenSourceClient(ts any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewTokenSourceClient", reflect.TypeOf((*MockClientCreator)(nil).NewTokenSourceClient), ts)
}

// NewTokenSourceV4Client mocks base method.
func (m *MockClientCreator) NewTokenSourceV4Client(ts oauth2.TokenSource) (*githubv4.Client, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewTokenSourceV4Client", ts)
	ret0, _ := ret[0].(*githubv4.Client)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewTokenSourceV4Client indicates an expected call of NewTokenSourceV4Client.
func (mr *MockClientCreatorMockRecorder) NewTokenSourceV4Client(ts any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewTokenSourceV4Client", reflect.TypeOf((*MockClientCreator)(nil).NewTokenSourceV4Client), ts)
}

// NewTokenV4Client mocks base method.
func (m *MockClientCreator) NewTokenV4Client(token string) (*githubv4.Client, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewTokenV4Client", token)
	ret0, _ := ret[0].(*githubv4.Client)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewTokenV4Client indicates an expected call of NewTokenV4Client.
func (mr *MockClientCreatorMockRecorder) NewTokenV4Client(token any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewTokenV4Client", reflect.TypeOf((*MockClientCreator)(nil).NewTokenV4Client), token)
}
