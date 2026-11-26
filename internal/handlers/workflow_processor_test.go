// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cilium/ariane/internal/config"
	github "github.com/google/go-github/v92/github"
	"github.com/rs/zerolog"
)

func Test_checkTriggerDependency(t *testing.T) {
	mockServer := setMockServer()
	defer mockServer.Close()
	mockURL := new(mockServer.URL + "/")
	client, err := github.NewClient(github.WithURLs(mockURL, mockURL))
	if err != nil {
		t.Fatalf("Failed to create GitHub client: %v", err)
	}

	var logger zerolog.Logger
	testCases := []struct {
		ArianeConfig   *config.ArianeConfig
		ExpectedResult bool
		ExpectedReason string
	}{
		{
			ArianeConfig: &config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"trigger": {
						Workflows: []string{"bar.yaml"},
					},
				},
			},
			ExpectedResult: true,
			ExpectedReason: "Workflow has successful workflow run",
		},
		{
			ArianeConfig: &config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"trigger": {
						Workflows: []string{"foobar.yaml"},
					},
				},
			},
			ExpectedResult: false,
			ExpectedReason: "Workflow has failed workflow run",
		},
		{
			ArianeConfig: &config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"trigger": {
						Workflows: []string{"eventually-passing.yaml"},
					},
				},
			},
			ExpectedResult: true,
			ExpectedReason: "Workflow has multiple failed runs and last one is successful",
		},
		{
			ArianeConfig: &config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"trigger": {
						Workflows: []string{"eventually-failing.yaml"},
					},
				},
			},
			ExpectedResult: false,
			ExpectedReason: "Workflow has multiple failed runs and last one is failed",
		},
		{
			ArianeConfig: &config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"trigger": {
						Workflows: []string{"bar.yaml", "foobar.yaml"},
					},
				},
			},
			ExpectedResult: false,
			ExpectedReason: "Multiple workflows, one failed",
		},
		{
			ArianeConfig: &config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"trigger": {
						Workflows: []string{"bar.yaml", "eventually-passing.yaml"},
					},
				},
			},
			ExpectedResult: true,
			ExpectedReason: "Multiple workflows, all successful",
		},
		{
			ArianeConfig: &config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"trigger": {
						Workflows: []string{"in-progress.yaml"},
					},
				},
			},
			ExpectedResult: false,
			ExpectedReason: "Dependency still in progress",
		},
		{
			ArianeConfig: &config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"trigger": {
						Workflows: []string{"skipped.yaml"},
					},
				},
			},
			ExpectedResult: true,
			ExpectedReason: "Dependency skipped",
		},
	}
	for i, testCase := range testCases {
		processor := WorkflowProcessor{
			client:       client,
			arianeConfig: testCase.ArianeConfig,
			owner:        "owner",
			repo:         "repo",
			logger:       logger,
			runDelay:     0,
		}
		result, _, err := processor.checkTriggerDependency(context.Background(), "trigger", "mock-sha", "mock-ref")
		if err != nil {
			t.Errorf(`[TEST%v] checkTriggerDependency returned an unexpected error: %v`, i, err)
		}

		if result != testCase.ExpectedResult {
			t.Errorf(
				`[TEST%v] checkTriggerDependency failed.
				result: %v, expected: %v
				Expected reason to pass the test: %v`,
				i, result, testCase.ExpectedResult, testCase.ExpectedReason)
		}
	}
}

func Test_markWorkflowAsSkipped(t *testing.T) {
	mux := http.NewServeMux()
	// The workflows API returns the name from the default branch, which can
	// differ from the name at the ref the workflow is dispatched on.
	mux.HandleFunc("/repos/owner/repo/actions/workflows/renamed.yaml", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(&github.Workflow{Name: new("New Name")}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("/repos/owner/repo/contents/.github/workflows/renamed.yaml", func(w http.ResponseWriter, r *http.Request) {
		if ref := r.URL.Query().Get("ref"); ref != "mock-ref" {
			http.Error(w, "unexpected ref "+ref, http.StatusNotFound)
			return
		}
		fileContent := "name: Old Name\n"
		if err := json.NewEncoder(w).Encode(github.RepositoryContent{Content: &fileContent}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	var created github.CreateCheckRunOptions
	mux.HandleFunc("POST /repos/owner/repo/check-runs", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})
	mux.HandleFunc("/repos/owner/repo/commits/mock-sha/check-runs", func(w http.ResponseWriter, r *http.Request) {
		result := github.ListCheckRunsResults{Total: new(0)}
		if name := r.URL.Query().Get("check_name"); name != "" && name == created.Name {
			result = github.ListCheckRunsResults{
				Total:     new(1),
				CheckRuns: []*github.CheckRun{{Name: new(name), Conclusion: created.Conclusion}},
			}
		}
		if err := json.NewEncoder(w).Encode(result); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	mockServer := httptest.NewServer(mux)
	defer mockServer.Close()
	mockURL := new(mockServer.URL + "/")
	client, err := github.NewClient(github.WithURLs(mockURL, mockURL))
	if err != nil {
		t.Fatalf("Failed to create GitHub client: %v", err)
	}

	processor := WorkflowProcessor{
		client: client,
		owner:  "owner",
		repo:   "repo",
	}
	if err := processor.markWorkflowAsSkipped(context.Background(), "renamed.yaml", "mock-sha", "mock-ref"); err != nil {
		t.Fatalf("markWorkflowAsSkipped returned an unexpected error: %v", err)
	}
	if created.Name != "Old Name" || created.HeadSHA != "mock-sha" {
		t.Errorf("skipped check run %q on %q, expected %q on %q", created.Name, created.HeadSHA, "Old Name", "mock-sha")
	}

	// The dependency lookup must find the skipped check under the same name.
	check, err := processor.getWorkflowCheck(context.Background(), "renamed.yaml", "mock-sha", "mock-ref")
	if err != nil {
		t.Fatalf("getWorkflowCheck did not find the skipped check run: %v", err)
	}
	if check.GetConclusion() != "skipped" {
		t.Errorf("check run conclusion: %q, expected %q", check.GetConclusion(), "skipped")
	}
}

func Test_shouldSkipWorkflow_statuses(t *testing.T) {
	testCases := []struct {
		status     string
		shouldSkip bool
	}{
		{status: "in_progress", shouldSkip: true},
		{status: "pending", shouldSkip: true},
		{status: "queued", shouldSkip: true},
		{status: "requested", shouldSkip: true},
		{status: "waiting", shouldSkip: true},
		{status: "cancelled", shouldSkip: false},
	}
	statusByWorkflow := make(map[string]string, len(testCases))
	for _, testCase := range testCases {
		statusByWorkflow[testCase.status+".yaml"] = testCase.status
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/actions/workflows/{workflow}/runs", func(w http.ResponseWriter, r *http.Request) {
		status, ok := statusByWorkflow[r.PathValue("workflow")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("head_sha") != "mock-sha" {
			http.Error(w, "unexpected head SHA", http.StatusBadRequest)
			return
		}

		runs := github.WorkflowRuns{
			TotalCount: new(1),
			WorkflowRuns: []*github.WorkflowRun{{
				Status:  new(status),
				HeadSHA: new("mock-sha"),
			}},
		}
		if err := json.NewEncoder(w).Encode(runs); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	mockServer := httptest.NewServer(mux)
	defer mockServer.Close()
	mockURL := new(mockServer.URL + "/")
	client, err := github.NewClient(github.WithURLs(mockURL, mockURL))
	if err != nil {
		t.Fatalf("Failed to create GitHub client: %v", err)
	}

	processor := &WorkflowProcessor{
		client:       client,
		arianeConfig: &config.ArianeConfig{},
		owner:        "owner",
		repo:         "repo",
		logger:       zerolog.Nop(),
	}

	for _, testCase := range testCases {
		t.Run(testCase.status, func(t *testing.T) {
			workflow := testCase.status + ".yaml"
			got := processor.shouldSkipWorkflow(context.Background(), workflow, "mock-sha")
			if got != testCase.shouldSkip {
				t.Errorf("shouldSkipWorkflow(%q) = %t, want %t", testCase.status, got, testCase.shouldSkip)
			}
		})
	}
}
