// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetStatusEmoji(t *testing.T) {
	testCases := []struct {
		name          string
		status        workflowStatusType
		expectedEmoji string
	}{
		{
			name:          "triggered status",
			status:        workflowStatusTriggered,
			expectedEmoji: "✅ Triggered",
		},
		{
			name:          "skipped status",
			status:        workflowStatusSkipped,
			expectedEmoji: "⏭️ Skipped",
		},
		{
			name:          "already completed status",
			status:        workflowStatusAlreadyCompleted,
			expectedEmoji: "✔️ Already Completed",
		},
		{
			name:          "failed status",
			status:        workflowStatusFailed,
			expectedEmoji: "❌ Failed to Trigger",
		},
		{
			name:          "failed to mark as skipped status",
			status:        workflowStatusFailedToMarkSkipped,
			expectedEmoji: "⚠️ Failed to Mark as Skipped",
		},
		{
			name:          "unknown status",
			status:        workflowStatusType("unknown"),
			expectedEmoji: "unknown",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			emoji := getStatusEmoji(tc.status)
			assert.Equal(t, tc.expectedEmoji, emoji)
		})
	}
}
