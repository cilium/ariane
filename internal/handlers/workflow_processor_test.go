// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package handlers

import (
	"context"
	"net/url"
	"testing"

	"github.com/cilium/ariane/internal/config"
	github "github.com/google/go-github/v83/github"
	"github.com/rs/zerolog"
)

func Test_checkTriggerDependency(t *testing.T) {
	mockServer := setMockServer()
	defer mockServer.Close()
	client := github.NewClient(nil)
	client.BaseURL, _ = url.Parse(mockServer.URL + "/")

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
		result, _, err := processor.checkTriggerDependency(context.Background(), "trigger", "mock-sha")
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
