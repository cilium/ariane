// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-github/v92/github"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

const (
	mergeGroupHeadSHA        = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	mergeGroupBaseRef        = "main"
	githubActionsIntegration = 15368 // GitHub Actions app, pinned checks carry this id
)

func TestMergeGroupHandler_Handles(t *testing.T) {
	handler := &MergeGroupHandler{}
	assert.Equal(t, []string{"merge_group"}, handler.Handles())
}

func TestMergeGroupHandler_InvalidPayload(t *testing.T) {
	handler := &MergeGroupHandler{}
	err := handler.Handle(context.Background(), "merge_group", "deliveryID", []byte(`not json`))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse merge_group event payload")
}

// checksJSON encodes check objects. any-source checks omit pinnedField.
func checksJSON(anySource, pinned []string, pinnedField string) string {
	checks := make([]string, 0, len(anySource)+len(pinned))
	for _, c := range anySource {
		checks = append(checks, fmt.Sprintf(`{"context":%q}`, c))
	}
	for _, c := range pinned {
		checks = append(checks, fmt.Sprintf(`{"context":%q,%q:%d}`, c, pinnedField, githubActionsIntegration))
	}
	return strings.Join(checks, ",")
}

func classicBody(anySource, pinned []string) string {
	return fmt.Sprintf(`{"required_status_checks":{"checks":[%s]}}`, checksJSON(anySource, pinned, "app_id"))
}

func rulesBody(anySource, pinned []string) string {
	return fmt.Sprintf(`[{"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":false,"required_status_checks":[%s]}}]`, checksJSON(anySource, pinned, "integration_id"))
}

// respond serves body and asserts the ref was shortened to the branch name. status 0 means 200.
func respond(t *testing.T, status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, mergeGroupBaseRef, r.PathValue("branch"))
		if status != 0 {
			w.WriteHeader(status)
		}
		_, err := fmt.Fprint(w, body)
		assert.NoError(t, err)
	}
}

// runMergeGroup drives the handler against stub endpoints and returns the
// stamped check names. every stamp is asserted to target the head SHA.
func runMergeGroup(t *testing.T, action string, expectClient bool, classic, rules http.HandlerFunc) ([]string, error) {
	var (
		mu      sync.Mutex
		stamped []string
	)

	mux := http.NewServeMux()
	mux.Handle("GET /repos/owner/repo/branches/{branch}/protection", classic)
	mux.Handle("GET /repos/owner/repo/rules/branches/{branch}", rules)
	mux.HandleFunc("POST /repos/owner/repo/check-runs", func(w http.ResponseWriter, r *http.Request) {
		var run struct {
			Name       string `json:"name"`
			HeadSHA    string `json:"head_sha"`
			Status     string `json:"status"`
			Conclusion string `json:"conclusion"`
		}
		if err := json.NewDecoder(r.Body).Decode(&run); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		assert.Equal(t, mergeGroupHeadSHA, run.HeadSHA)
		assert.Equal(t, "completed", run.Status)
		assert.Equal(t, "success", run.Conclusion)
		mu.Lock()
		stamped = append(stamped, run.Name)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(&github.CheckRun{ID: github.Ptr(int64(1))})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	mockURL := github.Ptr(server.URL + "/")
	client, err := github.NewClient(github.WithURLs(mockURL, mockURL))
	if err != nil {
		t.Fatalf("new github client: %v", err)
	}

	cc := NewMockClientCreator(gomock.NewController(t))
	if expectClient {
		cc.EXPECT().NewInstallationClient(int64(1)).Return(client, nil)
	}
	handler := &MergeGroupHandler{ClientCreator: cc}

	payload := []byte(fmt.Sprintf(`{
	  "action": %q,
	  "merge_group": {"head_sha": %q, "base_ref": "refs/heads/main"},
	  "repository": {"name": "repo", "owner": {"login": "owner"}},
	  "installation": {"id": 1}
	}`, action, mergeGroupHeadSHA))

	err = handler.Handle(context.Background(), "merge_group", "deliveryID", payload)

	mu.Lock()
	defer mu.Unlock()
	return stamped, err
}

func TestMergeGroupHandler_Handle(t *testing.T) {
	const notProtected = `{"message":"Branch not protected"}`

	testCases := []struct {
		name          string
		action        string
		classicStatus int
		classicBody   string
		rulesStatus   int
		rulesBody     string
		expectClient  bool
		expectErr     bool
		expectStamped []string
	}{
		{
			name:          "rulesets only (no classic protection)",
			action:        "checks_requested",
			classicStatus: http.StatusNotFound,
			classicBody:   notProtected,
			rulesBody:     rulesBody([]string{"ci/build", "ci/test"}, []string{"actions/lint"}),
			expectClient:  true,
			expectStamped: []string{"ci/build", "ci/test"},
		},
		{
			name:          "classic protection only (no rulesets)",
			action:        "checks_requested",
			classicBody:   classicBody([]string{"ci/build", "ci/test"}, []string{"actions/lint"}),
			rulesBody:     `[]`,
			expectClient:  true,
			expectStamped: []string{"ci/build", "ci/test"},
		},
		{
			name:          "union of classic and rulesets, deduped",
			action:        "checks_requested",
			classicBody:   classicBody([]string{"ci/build", "shared"}, nil),
			rulesBody:     rulesBody([]string{"ci/test", "shared"}, nil),
			expectClient:  true,
			expectStamped: []string{"ci/build", "ci/test", "shared"},
		},
		{
			name:          "no required checks anywhere stamps nothing",
			action:        "checks_requested",
			classicStatus: http.StatusNotFound,
			classicBody:   notProtected,
			rulesBody:     `[]`,
			expectClient:  true,
			expectStamped: nil,
		},
		{
			name:          "only pinned checks stamps nothing",
			action:        "checks_requested",
			classicStatus: http.StatusNotFound,
			classicBody:   notProtected,
			rulesBody:     rulesBody(nil, []string{"actions/lint", "actions/e2e"}),
			expectClient:  true,
			expectStamped: nil,
		},
		{
			name:          "both sources fail returns error and stamps nothing",
			action:        "checks_requested",
			classicStatus: http.StatusInternalServerError,
			classicBody:   `{"message":"boom"}`,
			rulesStatus:   http.StatusInternalServerError,
			rulesBody:     `{"message":"boom"}`,
			expectClient:  true,
			expectErr:     true,
			expectStamped: nil,
		},
		{
			name:          "classic errors while rulesets succeed surfaces the error",
			action:        "checks_requested",
			classicStatus: http.StatusInternalServerError,
			classicBody:   `{"message":"boom"}`,
			rulesBody:     rulesBody([]string{"ci/build"}, nil),
			expectClient:  true,
			expectErr:     true,
			expectStamped: nil,
		},
		{
			name:          "rulesets error while classic succeeds surfaces the error",
			action:        "checks_requested",
			classicBody:   classicBody([]string{"ci/build"}, nil),
			rulesStatus:   http.StatusInternalServerError,
			rulesBody:     `{"message":"boom"}`,
			expectClient:  true,
			expectErr:     true,
			expectStamped: nil,
		},
		{
			name:          "non checks_requested action is a no-op",
			action:        "destroyed",
			classicBody:   classicBody([]string{"ci/build"}, nil),
			rulesBody:     `[]`,
			expectClient:  false,
			expectStamped: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			stamped, err := runMergeGroup(t, tc.action, tc.expectClient,
				respond(t, tc.classicStatus, tc.classicBody),
				respond(t, tc.rulesStatus, tc.rulesBody))

			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.ElementsMatch(t, tc.expectStamped, stamped)
		})
	}
}

// TestMergeGroupHandler_RulesetPagination checks that collectRulesetChecks
// follows resp.NextPage across pages so checks on a later page still get
// stamped.
func TestMergeGroupHandler_RulesetPagination(t *testing.T) {
	rules := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			_, err := fmt.Fprint(w, rulesBody([]string{"ci/page2"}, nil))
			assert.NoError(t, err)
			return
		}
		// point go-github at page 2 through the Link header. only the page
		// query value matters for resp.NextPage
		w.Header().Set("Link", `<http://example.com/rules?page=2>; rel="next"`)
		_, err := fmt.Fprint(w, rulesBody([]string{"ci/page1"}, nil))
		assert.NoError(t, err)
	}

	stamped, err := runMergeGroup(t, "checks_requested", true,
		respond(t, http.StatusNotFound, `{"message":"Branch not protected"}`),
		rules)

	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"ci/page1", "ci/page2"}, stamped)
}
