// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/go-github/v75/github"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

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
	}{
		{
			config: config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"/cute": {[]string{"cte.yaml"}},
				},
			},
			comment:           "/cute",
			expectedSubmatch:  []string{"/cute"},
			expectedWorkflows: []string{"cte.yaml"},
		},
		{
			config: config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"/cute": {[]string{"cte.yaml"}},
				},
			},
			comment: "/cute cilium/cute-nationwide",
		},
		{
			config: config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					"/cute (.+)": {[]string{"cte.yaml"}},
				},
			},
			comment:           "/cute {\"repo\":\"zerohash\"}",
			expectedSubmatch:  []string{"/cute {\"repo\":\"zerohash\"}", "{\"repo\":\"zerohash\"}"},
			expectedWorkflows: []string{"cte.yaml"},
		},
		{
			config: config.ArianeConfig{
				Triggers: map[string]config.TriggerConfig{
					`\invalid-reg-exp`: {[]string{"invalid.yaml"}},
				},
			},
			comment: "/test invalid regex",
		},
	}
	for _, tt := range cases {
		actualSubmatch, actualWorkflows := tt.config.CheckForTrigger(ctx, tt.comment)

		assert.Equal(t, tt.expectedSubmatch, actualSubmatch)
		assert.Equal(t, tt.expectedWorkflows, actualWorkflows)
	}
}

func Test_ShouldRunOnlyWorkflows(t *testing.T) {
	config := &config.ArianeConfig{
		Triggers: map[string]config.TriggerConfig{
			"/foo":            {[]string{"foo.yaml"}},
			"/bar":            {[]string{"bar.yaml"}},
			"/enterprise-foo": {[]string{"enterprise-foo.yaml"}},
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
			"/foo":            {[]string{"foo.yaml"}},
			"/bar":            {[]string{"bar.yaml"}},
			"/enterprise-foo": {[]string{"enterprise-foo.yaml"}},
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
