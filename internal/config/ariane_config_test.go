// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/go-github/v83/github"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"

	"github.com/cilium/ariane/internal/config"
	"github.com/cilium/ariane/internal/log"
)

func Test_CheckForTrigger(t *testing.T) {
	logger := zerolog.New(os.Stdout)
	ctx := log.WithLogger(context.Background(), &logger)
	cases := []struct {
		config            config.ArianeConfig
		comment           string
		expectedSubmatch  []string
		expectedWorkflows []string
		expectedDependsOn []string
	}{
		{
			config: config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"/cute": {Workflows: []string{"cte.yaml"}},
				},
			},
			comment:           "/cute",
			expectedSubmatch:  []string{"/cute"},
			expectedWorkflows: []string{"cte.yaml"},
		},
		{
			config: config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"/cute": {Workflows: []string{"cte.yaml"}},
				},
			},
			comment: "/cute cilium/cute-nationwide",
		},
		{
			config: config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"/cute (.+)": {Workflows: []string{"cte.yaml"}},
				},
			},
			comment:           "/cute {\"repo\":\"zerohash\"}",
			expectedSubmatch:  []string{"/cute {\"repo\":\"zerohash\"}", "{\"repo\":\"zerohash\"}"},
			expectedWorkflows: []string{"cte.yaml"},
		},
		{
			config: config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					`\invalid-reg-exp`: {Workflows: []string{"invalid.yaml"}},
				},
			},
			comment: "/test invalid regex",
		},
		{
			config: config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"/test":   {Workflows: []string{"test.yaml"}},
					"/deploy": {Workflows: []string{"deploy.yaml"}, DependsOn: []string{"/test"}},
				},
			},
			comment:           "/deploy",
			expectedSubmatch:  []string{"/deploy"},
			expectedDependsOn: []string{"/test"},
			expectedWorkflows: []string{"deploy.yaml"},
		},
		{
			config: config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"/test":   {Workflows: []string{"test.yaml"}},
					"/deploy": {Workflows: []string{"deploy.yaml"}, DependsOn: []string{"/test"}},
				},
			},
			comment:           "/deploy",
			expectedSubmatch:  []string{"/deploy"},
			expectedDependsOn: []string{"/test"},
			expectedWorkflows: []string{"deploy.yaml"},
		},
	}
	for i, tt := range cases {
		actualSubmatch, actualWorkflows, actualDependsOn := tt.config.CheckForTrigger(ctx, tt.comment)

		assert.Equal(t, tt.expectedSubmatch, actualSubmatch, "for index: %v", i)
		assert.Equal(t, tt.expectedWorkflows, actualWorkflows, "for index: %v", i)
		assert.Equal(t, tt.expectedDependsOn, actualDependsOn, "for index: %v", i)
	}
}

func TestArianeConfigMerge(t *testing.T) {
	cases := []struct {
		config       *config.ArianeConfig
		otherConfig  *config.ArianeConfig
		mergedConfig *config.ArianeConfig
	}{
		{
			config: &config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"/foo": {Workflows: []string{"foo.yaml"}},
					"/bar": {Workflows: []string{"bar.yaml"}},
				},
			},
			otherConfig: &config.ArianeConfig{},
			mergedConfig: &config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"/foo": {Workflows: []string{"foo.yaml"}},
					"/bar": {Workflows: []string{"bar.yaml"}},
				},
			},
		},
		{
			config: &config.ArianeConfig{},
			otherConfig: &config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"/foo": {Workflows: []string{"foo.yaml"}},
					"/bar": {Workflows: []string{"bar.yaml"}},
				},
			},
			mergedConfig: &config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"/foo": {Workflows: []string{"foo.yaml"}},
					"/bar": {Workflows: []string{"bar.yaml"}},
				},
			},
		},
		{
			config: &config.ArianeConfig{},
			otherConfig: &config.ArianeConfig{
				AllowedTeams: []string{"team1"},
			},
			mergedConfig: &config.ArianeConfig{
				AllowedTeams: []string{"team1"},
			},
		},
		{
			config: &config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"/foo": {Workflows: []string{"foo.yaml"}},
				},
				Workflows: map[string]config.WorkflowPathsRegexConfig{
					"foo.yaml": {
						PathsIgnoreRegex: "(c|d)/",
					},
				},
				AllowedTeams: []string{
					"team1",
				},
			},
			otherConfig: &config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"/bar": {Workflows: []string{"bar.yaml"}},
				},
				Workflows: map[string]config.WorkflowPathsRegexConfig{
					"bar.yaml": {
						PathsRegex: "(x|y)/",
					},
				},
				AllowedTeams: []string{
					"team2",
				},
			},
			mergedConfig: &config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"/foo": {Workflows: []string{"foo.yaml"}},
					"/bar": {Workflows: []string{"bar.yaml"}},
				},
				Workflows: map[string]config.WorkflowPathsRegexConfig{
					"foo.yaml": {
						PathsIgnoreRegex: "(c|d)/",
					},
					"bar.yaml": {
						PathsRegex: "(x|y)/",
					},
				},
				AllowedTeams: []string{
					"team1",
					"team2",
				},
			},
		},
		{
			config: &config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"/foo": {Workflows: []string{"foo.yaml"}},
				},
				Workflows: map[string]config.WorkflowPathsRegexConfig{
					"foo.yaml": {
						PathsIgnoreRegex: "(c|d)/",
					},
				},
				AllowedTeams: []string{
					"team1",
					"team3",
				},
			},
			otherConfig: &config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"/foo": {Workflows: []string{"enterprise-foo.yaml"}},
					"/bar": {Workflows: []string{"bar.yaml"}},
				},
				Workflows: map[string]config.WorkflowPathsRegexConfig{
					"bar.yaml": {
						PathsRegex: "(x|y)/",
					},
					"foo.yaml": {
						PathsIgnoreRegex: ".*/",
					},
					"enterprise-foo.yaml": {
						PathsRegex: "(y|z)/",
					},
				},
				AllowedTeams: []string{
					"team1",
					"team2",
				},
			},
			mergedConfig: &config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"/bar": {Workflows: []string{"bar.yaml"}},
					"/foo": {Workflows: []string{"foo.yaml", "enterprise-foo.yaml"}},
				},
				Workflows: map[string]config.WorkflowPathsRegexConfig{
					"foo.yaml": {
						PathsIgnoreRegex: ".*/",
					},
					"bar.yaml": {
						PathsRegex: "(x|y)/",
					},
					"enterprise-foo.yaml": {
						PathsRegex: "(y|z)/",
					},
				},
				AllowedTeams: []string{
					"team1",
					"team3",
					"team2",
				},
			},
		},
	}
	for _, tt := range cases {
		mergedConfig := tt.config.Merge(tt.otherConfig)

		assert.Equal(t, tt.mergedConfig, mergedConfig)
	}
}

func Test_ShouldRunOnlyWorkflows(t *testing.T) {
	config := &config.ArianeConfig{
		Triggers: map[string]config.TriggerConfig{
			"/foo":            {Workflows: []string{"foo.yaml"}},
			"/bar":            {Workflows: []string{"bar.yaml"}},
			"/enterprise-foo": {Workflows: []string{"enterprise-foo.yaml"}},
		},
		Workflows: map[string]config.WorkflowPathsRegexConfig{},
		AllowedTeams: []string{
			"team1",
			"team2",
		},
	}

	testCases := []struct {
		Workflow       string
		FilenamesJson  []byte
		ExpectedResult bool
		ExpectedReason string
	}{
		{
			Workflow:       "foo.yaml",
			FilenamesJson:  []byte(`[{"filename": ".github/workflows/foo.yaml"}, {"filename": "test/testdata.json"}, {"filename": "nocode/Documentation/operations-guide.rst"}]`),
			ExpectedResult: true,
			ExpectedReason: "changes exist on the \"workflow\" var (foo.yaml) under .github/workflows/",
		},
		{
			Workflow:       "foo.yaml",
			FilenamesJson:  []byte(`[{"filename": ".github/workflows/bar.yaml"}, {"filename": "test/testdata.json"}, {"filename": "nocode/Documentation/operations-guide.rst"}]`),
			ExpectedResult: true,
			ExpectedReason: "a workflow was changed, however not foo.yaml - Nevertheless, non-workflow files were updated, hence foo.yaml needs to run",
		},
		{
			Workflow:       "foo.yaml",
			FilenamesJson:  []byte(`[{"filename": "test/testdata.json"}, {"filename": "nocode/Documentation/operations-guide.rst"}]`),
			ExpectedResult: true,
			ExpectedReason: "No workflows were updated - however, there are other files changed, hence the foo.yaml workflow needs to runs",
		},
		{
			Workflow:       "foo.yaml",
			FilenamesJson:  []byte(`[{"filename": "test/testdata.json"}, {"filename": "Documentation/operations-guide.rst"}]`),
			ExpectedResult: true,
			ExpectedReason: "No workflows were updated, and no regexps exist - there are other files changed, hence the foo.yaml workflow needs to runs",
		},
		{
			Workflow:       "foo.yaml",
			FilenamesJson:  []byte(`[]`),
			ExpectedResult: false,
			ExpectedReason: "No changes committed, hence nothing new to test",
		},
		{
			Workflow:       "bar.yaml",
			FilenamesJson:  []byte(`[{"filename": "test/testdata.json"}, {"filename": "x/lib3/handlers/handler.go"}]`),
			ExpectedResult: true,
			ExpectedReason: "No workflows were updated, and no regexps exist - there are other files changed, hence the foo.yaml workflow needs to runs.",
		},
		{
			Workflow:       "enterprise-foo.yaml",
			FilenamesJson:  []byte(`[{"filename": ".github/workflows/foo.yaml"}, {"filename": ".github/workflows/config/set-env"}]`),
			ExpectedResult: false,
			ExpectedReason: "Only workflows were changed, but not the enterprise-foo.yaml one. No need to run the workflow.",
		},
	}

	for idx, testCase := range testCases {
		files := []*github.CommitFile{}
		if err := json.Unmarshal(testCase.FilenamesJson, &files); err != nil {
			t.Errorf("[TEST%v] ShouldRunOnlyWorkflow failed.\nCould not unmarshal the mocked json data.", idx+1)
		}
		result := config.ShouldRunOnlyWorkflows(context.Background(), testCase.Workflow, files)
		if result != testCase.ExpectedResult {
			t.Errorf("[TEST%v] ShouldRunOnlyWorkflows failed.\nfiles: %v;\nExpected reason to pass the test: %v", idx+1, files, testCase.ExpectedReason)
		}
	}
}

func Test_ShouldRunWorkflow(t *testing.T) {
	config := &config.ArianeConfig{
		Triggers: map[string]config.TriggerConfig{
			"/foo":            {Workflows: []string{"foo.yaml"}},
			"/bar":            {Workflows: []string{"bar.yaml"}},
			"/enterprise-foo": {Workflows: []string{"enterprise-foo.yaml"}},
		},
		Workflows: map[string]config.WorkflowPathsRegexConfig{
			"bar.yaml": {
				PathsRegex: "(x|y)/",
			},
			"foo.yaml": {
				PathsIgnoreRegex: "(test|Documentation|myproject)/",
			},
			"enterprise-foo.yaml": {},
			"foobar.yaml": {
				PathsRegex:       "(x|y)/",
				PathsIgnoreRegex: "(test|Documentation|myproject)/",
			},
		},
		AllowedTeams: []string{
			"team1",
			"team2",
		},
	}

	testCases := []struct {
		Workflow       string
		FilenamesJson  []byte
		ExpectedResult bool
		ExpectedReason string
	}{
		// foo.yaml only defines paths-ignore-regex
		{
			Workflow:       "foo.yaml",
			FilenamesJson:  []byte(`[{"filename": ".github/workflows/foo.yaml"}, {"filename": "test/testdata.json"}, {"filename": "nocode/Documentation/operations-guide.rst"}]`),
			ExpectedResult: true,
			ExpectedReason: "changes exist on 3 files, and only one needs to be ignored (test/testdata.json) - not matching all 3 files. WF runs.",
		},
		{
			Workflow:       "foo.yaml",
			FilenamesJson:  []byte(`[{"filename": ".github/workflows/foo.yaml"}, {"filename": ".github/workflows/bar.yaml"}, {"filename": "test/testdata.json"}, {"filename": "Documentation/operations-guide.rst"}]`),
			ExpectedResult: true,
			ExpectedReason: "changes exist on 4 files, including the workflow to trigger - besides other workflows being modified, as well as matching files on paths-ignore-regex",
		},
		{
			Workflow:       "foo.yaml",
			FilenamesJson:  []byte(`[{"filename": ".github/workflows/bar.yaml"}, {"filename": "test/testdata.json"}, {"filename": "Documentation/operations-guide.rst"}]`),
			ExpectedResult: false,
			ExpectedReason: "changes exist on a file that is not matched by paths-ignore-regex, but it is another workflow",
		},
		{
			Workflow:       "foo.yaml",
			FilenamesJson:  []byte(`[{"filename": "test/testdata.json"}, {"filename": "nocode/Documentation/operations-guide.rst"}]`),
			ExpectedResult: true,
			ExpectedReason: "changes exist on a file within the nocode folder (the regexp is actually '^Documentation/')",
		},
		{
			Workflow:       "foo.yaml",
			FilenamesJson:  []byte(`[{"filename": "test/testdata.json"}, {"filename": "Documentation/operations-guide.rst"}]`),
			ExpectedResult: false,
			ExpectedReason: "all changes are matched by paths-ignore-regex",
		},
		{
			Workflow:       "foo.yaml",
			FilenamesJson:  []byte(`[]`),
			ExpectedResult: false,
			ExpectedReason: "No changes committed, hence nothing new to test",
		},
		// bar.yaml only defines paths-regex
		{
			Workflow:       "bar.yaml",
			FilenamesJson:  []byte(`[{"filename": "test/testdata.json"}, {"filename": "x/lib3/handlers/handler.go"}]`),
			ExpectedResult: true,
			ExpectedReason: "changes match a file on paths-regex. Workflow will run.",
		},
		{
			Workflow:       "bar.yaml",
			FilenamesJson:  []byte(`[{"filename": "test/testdata.json"}, {"filename": "Documentation/operations-guide.rst"}]`),
			ExpectedResult: false,
			ExpectedReason: "changes do not match paths-regex, and the workflow to trigger has not been modified. Workflow will not run.",
		},
		{
			Workflow:       "bar.yaml",
			FilenamesJson:  []byte(`[{"filename": "test/testdata.json"}, {"filename": "Documentation/operations-guide.rst"}, {"filename": ".github/workflows/bar.yaml"}]`),
			ExpectedResult: true,
			ExpectedReason: "changes do not match paths-regex, but the workflow to trigger has changed. Workflow will run.",
		},
		// enterprise-foo.yaml does not define paths-regex nor paths-ignore-regex
		{
			Workflow:       "enterprise-foo.yaml",
			FilenamesJson:  []byte(`[{"filename": ".github/workflows/foo.yaml"}, {"filename": ".github/workflows/bar.yaml"}, {"filename": "test/testdata.json"}, {"filename": "nocode/Documentation/operations-guide.rst"}]`),
			ExpectedResult: true,
			ExpectedReason: "changes exist and no paths-regex or paths-ignore-regex are evaluated - no matter 2 out of 4 files are other workflows than the one that will be triggered",
		},
		{
			Workflow:       "enterprise-foo.yaml",
			FilenamesJson:  []byte(`[{"filename": ".github/workflows/foo.yaml"}, {"filename": ".github/workflows/bar.yaml"}]`),
			ExpectedResult: false,
			ExpectedReason: "changes exist and no paths-regex or paths-ignore-regex are evaluated - however, changes on other workflows do not qualify to trigger the actual workflow (enterprise-foo.yaml). WF will not run",
		},
		// foobar.yaml does define both paths-regex and paths-ignore-regex (default: run the workflow)
		{
			Workflow:       "foobar.yaml",
			FilenamesJson:  []byte(`[{"filename": ".github/workflows/foo.yaml"}, {"filename": ".github/workflows/bar.yaml"}]`),
			ExpectedResult: true,
			ExpectedReason: "changes exist and both paths-regex and paths-ignore-regex are defined - default to run the workflow without evaluating any further",
		},
		{
			Workflow:       "foobar.yaml",
			FilenamesJson:  []byte(`[{"filename": "Documentation/operations-guide.rst"}]`),
			ExpectedResult: true,
			ExpectedReason: "changes exist and both paths-regex and paths-ignore-regex are defined - default to run the workflow without evaluating any further",
		},
		{
			Workflow:       "foobar.yaml",
			FilenamesJson:  []byte(`[]`),
			ExpectedResult: false,
			ExpectedReason: "no changes exist, despite both paths-regex and paths-ignore-regex being defined - the workflow will not run",
		},
	}

	for idx, testCase := range testCases {
		files := []*github.CommitFile{}
		if err := json.Unmarshal(testCase.FilenamesJson, &files); err != nil {
			t.Errorf("[TEST%v] ShouldrunWorkflow failed.\nCould not unmarshal the mocked json data.", idx+1)
		}
		result := config.ShouldRunWorkflow(context.Background(), testCase.Workflow, files)
		if result != testCase.ExpectedResult {
			t.Errorf("[TEST%v] ShouldRunWorkflow failed.\nfiles: %v;\nExpected reason to pass the test: %v", idx+1, files, testCase.ExpectedReason)
		}
	}
}

func TestGetVerbose(t *testing.T) {
	testCases := []struct {
		name           string
		config         *config.ArianeConfig
		expectedResult bool
	}{
		{
			name: "Feedback.Verbose is nil (default zero value)",
			config: &config.ArianeConfig{
				Feedback: config.FeedbackConfig{
					Verbose: nil,
				},
			},
			expectedResult: false,
		},
		{
			name: "Verbose is true",
			config: &config.ArianeConfig{
				Feedback: config.FeedbackConfig{
					Verbose: boolPtr(true),
				},
			},
			expectedResult: true,
		},
		{
			name: "Verbose is false",
			config: &config.ArianeConfig{
				Feedback: config.FeedbackConfig{
					Verbose: boolPtr(false),
				},
			},
			expectedResult: false,
		},
		{
			name:           "Empty config with zero value Feedback",
			config:         &config.ArianeConfig{},
			expectedResult: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.config.GetVerbose()
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}

func TestGetWorkflowsReport(t *testing.T) {
	testCases := []struct {
		name           string
		config         *config.ArianeConfig
		expectedResult bool
	}{
		{
			name: "Feedback.WorkflowsReport is nil (default zero value)",
			config: &config.ArianeConfig{
				Feedback: config.FeedbackConfig{
					WorkflowsReport: nil,
				},
			},
			expectedResult: false,
		},
		{
			name: "WorkflowsReport is true",
			config: &config.ArianeConfig{
				Feedback: config.FeedbackConfig{
					WorkflowsReport: boolPtr(true),
				},
			},
			expectedResult: true,
		},
		{
			name: "WorkflowsReport is false",
			config: &config.ArianeConfig{
				Feedback: config.FeedbackConfig{
					WorkflowsReport: boolPtr(false),
				},
			},
			expectedResult: false,
		},
		{
			name:           "Empty config with zero value Feedback",
			config:         &config.ArianeConfig{},
			expectedResult: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.config.GetWorkflowsReport()
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}

// boolPtr is a helper function to create a pointer to a bool
func boolPtr(b bool) *bool {
	return &b
}

func TestGetVerbose_WithYAMLParsing(t *testing.T) {
	testCases := []struct {
		name           string
		yamlConfig     string
		expectedResult bool
	}{
		{
			name: "Feedback omitted from YAML config",
			yamlConfig: `
triggers:
  /test:
    workflows: ["test.yaml"]
allowed-teams:
  - team1
`,
			expectedResult: false,
		},
		{
			name: "Feedback present but verbose omitted",
			yamlConfig: `
feedback:
  workflows-report: true
triggers:
  /test:
    workflows: ["test.yaml"]
`,
			expectedResult: false,
		},
		{
			name: "Verbose explicitly set to true",
			yamlConfig: `
feedback:
  verbose: true
triggers:
  /test:
    workflows: ["test.yaml"]
`,
			expectedResult: true,
		},
		{
			name: "Verbose explicitly set to false",
			yamlConfig: `
feedback:
  verbose: false
triggers:
  /test:
    workflows: ["test.yaml"]
`,
			expectedResult: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var cfg config.ArianeConfig
			err := yaml.Unmarshal([]byte(tc.yamlConfig), &cfg)
			assert.NoError(t, err)

			result := cfg.GetVerbose()
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}

func TestGetWorkflowsReport_WithYAMLParsing(t *testing.T) {
	testCases := []struct {
		name           string
		yamlConfig     string
		expectedResult bool
	}{
		{
			name: "Feedback omitted from YAML config",
			yamlConfig: `
triggers:
  /test:
    workflows: ["test.yaml"]
allowed-teams:
  - team1
`,
			expectedResult: false,
		},
		{
			name: "Feedback present but workflows-report omitted",
			yamlConfig: `
feedback:
  verbose: true
triggers:
  /test:
    workflows: ["test.yaml"]
`,
			expectedResult: false,
		},
		{
			name: "WorkflowsReport explicitly set to true",
			yamlConfig: `
feedback:
  workflows-report: true
triggers:
  /test:
    workflows: ["test.yaml"]
`,
			expectedResult: true,
		},
		{
			name: "WorkflowsReport explicitly set to false",
			yamlConfig: `
feedback:
  workflows-report: false
triggers:
  /test:
    workflows: ["test.yaml"]
`,
			expectedResult: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var cfg config.ArianeConfig
			err := yaml.Unmarshal([]byte(tc.yamlConfig), &cfg)
			assert.NoError(t, err)

			result := cfg.GetWorkflowsReport()
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}
