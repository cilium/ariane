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

	github "github.com/google/go-github/v75/github"
	"github.com/cilium/ariane/internal/config"
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
		ClientCreator: mockClientCreator,
		RunDelay:      time.Second,
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
		ClientCreator: mockClientCreator,
		RunDelay:      time.Second,
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
	mockCtrl := gomock.NewController(t)
	mockClientCreator := NewMockClientCreator(mockCtrl)
	mockClientCreator.EXPECT().NewInstallationClient(int64(0)).Return(nil, nil)

	handler := &PRCommentHandler{
		ClientCreator: mockClientCreator,
		RunDelay:      time.Second,
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
		ClientCreator: mockClientCreator,
		RunDelay:      time.Second,
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
		ClientCreator: mockClientCreator,
		RunDelay:      time.Second,
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
		ClientCreator: mockClientCreator,
		RunDelay:      time.Second,
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
		ClientCreator: mockClientCreator,
		RunDelay:      time.Second * 30000,
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
		ClientCreator: mockClientCreator,
		RunDelay:      time.Second,
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
					Ref: github.String("pr/owner/mybugfix"),
					SHA: github.String("mock-sha"),
					Repo: &github.Repository{
						Owner: &github.User{Login: github.String("owner")},
						Name:  github.String("repo"),
					},
				},
				Base: &github.PullRequestBranch{
					Ref: github.String("main"),
				},
			},
		}
		if err := json.NewEncoder(w).Encode(prs); err != nil {
			http.Error(w, "setMockServer: could not encode the PRs payload in JSON for the HTTP response.", http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("/repos/owner/repo/pulls/0", func(w http.ResponseWriter, r *http.Request) {
		pr := &github.PullRequest{
			Head: &github.PullRequestBranch{
				Ref: github.String("pr/owner/mybugfix"),
				SHA: github.String("mock-sha"),
				Repo: &github.Repository{
					Owner: &github.User{Login: github.String("owner")},
					Name:  github.String("repo"),
				},
			},
			Base: &github.PullRequestBranch{
				Ref: github.String("main"),
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
				Filename: github.String(".github/workflows/foo.yaml"),
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
				State: github.String("active"),
			}
		case "unknownauthor":
			membership = &github.Membership{
				State: github.String("pending"),
			}
		}

		if err := json.NewEncoder(w).Encode(membership); err != nil {
			http.Error(w, "setMockServer: could not encode the membership payload in JSON for the HTTP response.", http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("POST /repos/owner/repo/actions/workflows/foo.yaml/dispatches", func(w http.ResponseWriter, r *http.Request) {
		// https://docs.github.com/en/rest/actions/workflows?apiVersion=2022-11-28#create-a-workflow-dispatch-event
		w.WriteHeader(http.StatusNoContent)
		if _, err := w.Write([]byte(fmt.Sprintf("Status: %v\n", http.StatusNoContent))); err != nil {
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
				TotalCount:   github.Int(0),
				WorkflowRuns: []*github.WorkflowRun{},
			}
		} else if workflow == "foo.yaml" {
			workflowRuns = &github.WorkflowRuns{
				TotalCount: github.Int(2),
				WorkflowRuns: []*github.WorkflowRun{
					{
						ID:      github.Int64(1),
						Status:  github.String("cancelled"),
						HeadSHA: github.String(SHA),
					},
				},
			}
		} else if workflow == "bar.yaml" {
			workflowRuns = &github.WorkflowRuns{
				TotalCount: github.Int(1),
				WorkflowRuns: []*github.WorkflowRun{
					{
						ID:         github.Int64(2),
						Status:     github.String("completed"),
						Conclusion: github.String("success"),
						HeadSHA:    github.String(SHA),
					},
				},
			}
		} else if workflow == "foobar.yaml" {
			workflowRuns = &github.WorkflowRuns{
				TotalCount: github.Int(1),
				WorkflowRuns: []*github.WorkflowRun{
					{
						ID:         github.Int64(99),
						Status:     github.String("completed"),
						Conclusion: github.String("failure"),
						HeadSHA:    github.String(SHA),
					},
				},
			}
		} else {
			workflowRuns = &github.WorkflowRuns{
				TotalCount:   github.Int(0),
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
			TotalCount: github.Int(3),
			Jobs: []*github.WorkflowJob{
				{
					ID:    github.Int64(1),
					RunID: github.Int64(99),
					Name:  github.String("Installation and Conformance"),
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
		if _, err := w.Write([]byte(fmt.Sprintf("Status: %v\n", http.StatusCreated))); err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("POST /repos/owner/repo/issues/comments/1/reactions", func(w http.ResponseWriter, r *http.Request) {
		// https://docs.github.com/en/rest/reactions/reactions?apiVersion=2022-11-28#create-reaction-for-an-issue-comment
		reaction := &github.Reaction{
			ID:      github.Int64(1),
			Content: github.String(r.PostFormValue("content")),
		}
		if err := json.NewEncoder(w).Encode(reaction); err != nil {
			http.Error(w, "setMockServer: could not encode the reaction payload in JSON for the HTTP response.", http.StatusInternalServerError)
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
