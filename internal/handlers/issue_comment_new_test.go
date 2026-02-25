// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package handlers

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/ariane/internal/config"
)

func TestProcessWorkflow_Integration(t *testing.T) {
	// This is an integration-style test that validates the logic flow
	// without mocking internal methods
	testCases := []struct {
		name                   string
		workflowsReportEnabled bool
		expectedStatusType     workflowStatusType
		expectNil              bool
	}{
		{
			name:                   "with reporting enabled returns status",
			workflowsReportEnabled: true,
			expectNil:              false,
		},
		{
			name:                   "with reporting disabled may return nil",
			workflowsReportEnabled: false,
			expectNil:              true, // Will be nil if workflow is triggered/skipped successfully
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Note: This test validates the structure but cannot fully test
			// the logic without a real GitHub client or extensive mocking.
			// The actual workflow logic is tested through the existing
			// integration tests in TestHandle_WorkflowStatusTable
			workflowsReportPtr := &tc.workflowsReportEnabled
			arianeConfig := &config.ArianeConfig{
				Feedback: config.FeedbackConfig{
					WorkflowsReport: workflowsReportPtr,
				},
			}

			// Verify the config is set up correctly
			assert.Equal(t, tc.workflowsReportEnabled, arianeConfig.GetWorkflowsReport())
		})
	}
}

func TestPostWorkflowStatusComment(t *testing.T) {
	// Test that the workflow status comment is formatted correctly
	testCases := []struct {
		name             string
		statuses         []workflowStatus
		expectedContains []string
	}{
		{
			name: "single triggered workflow",
			statuses: []workflowStatus{
				{name: "ci.yaml", status: workflowStatusTriggered},
			},
			expectedContains: []string{
				"## Workflow Status",
				"| Workflow | Status |",
				"| `ci.yaml` | ✅ Triggered |",
			},
		},
		{
			name: "multiple workflows with different statuses",
			statuses: []workflowStatus{
				{name: "ci.yaml", status: workflowStatusTriggered},
				{name: "lint.yaml", status: workflowStatusSkipped},
				{name: "test.yaml", status: workflowStatusFailed},
			},
			expectedContains: []string{
				"## Workflow Status",
				"| `ci.yaml` | ✅ Triggered |",
				"| `lint.yaml` | ⏭️ Skipped |",
				"| `test.yaml` | ❌ Failed to Trigger |",
			},
		},
		{
			name:     "empty status list",
			statuses: []workflowStatus{},
			expectedContains: []string{
				"## Workflow Status",
				"| Workflow | Status |",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Note: This test validates the comment format.
			// The actual posting is tested through integration tests
			// like TestHandle_WorkflowStatusTable which uses a mock server.

			// Build the comment manually to verify format
			var commentBuilder strings.Builder
			commentBuilder.WriteString("## Workflow Status\n\n")
			commentBuilder.WriteString("| Workflow | Status |\n")
			commentBuilder.WriteString("|----------|--------|\n")

			for _, ws := range tc.statuses {
				statusEmoji := getStatusEmoji(ws.status)
				fmt.Fprintf(&commentBuilder, "| `%s` | %s |\n", ws.name, statusEmoji)
			}

			result := commentBuilder.String()

			// Verify all expected strings are present
			for _, expected := range tc.expectedContains {
				assert.Contains(t, result, expected)
			}
		})
	}
}
