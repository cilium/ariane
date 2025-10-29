// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/go-github/v75/github"
	"gopkg.in/yaml.v3"

	"github.com/cilium/ariane/internal/log"
)

const (
	ArianeConfigPath = ".github/ariane-config.yaml"
)

type ArianeConfig struct {
	Triggers     map[string]TriggerConfig            `yaml:"triggers"`
	Workflows    map[string]WorkflowPathsRegexConfig `yaml:"workflows"`
	AllowedTeams []string                            `yaml:"allowed-teams,omitempty"`
}

type TriggerConfig struct {
	Workflows []string `yaml:"workflows"`
}

type WorkflowPathsRegexConfig struct {
	PathsRegex       string `yaml:"paths-regex"`
	PathsIgnoreRegex string `yaml:"paths-ignore-regex"`
}

func GetArianeConfigFromRepository(client *github.Client, ctx context.Context, owner string, repoName string, ref string) (*ArianeConfig, error) {
	fileContent, _, _, err := client.Repositories.GetContents(ctx, owner, repoName, ArianeConfigPath, &github.RepositoryContentGetOptions{Ref: ref})
	if err != nil {
		return nil, fmt.Errorf("failed downloading config file from repository: %w", err)
	}

	configString, err := fileContent.GetContent()
	if err != nil {
		return nil, fmt.Errorf("failed reading config file: %w", err)
	}

	var config ArianeConfig
	if err = yaml.Unmarshal([]byte(configString), &config); err != nil {
		return nil, fmt.Errorf("failed parsing configuration file: %w", err)
	}

	return &config, err
}

// CheckForTrigger checks if any trigger registered in config match given comment.
func (config *ArianeConfig) CheckForTrigger(ctx context.Context, comment string) ([]string, []string) {
	for regex, trigger := range config.Triggers {
		re, err := regexp.Compile(`^` + regex + `$`)
		if err != nil {
			log.FromContext(ctx).Err(err).Msgf("cannot compile regexp %q", regex)
			continue
		}
		submatch := re.FindStringSubmatch(comment)
		if submatch != nil {
			return submatch, trigger.Workflows
		}
	}
	return nil, nil
}

// ShouldRunOnlyWorkflows checks given changed files against .github/workflow pattern
// Return false if only workflow files changed and the current workflow file is not changed
// Return true otherwise
func (config *ArianeConfig) ShouldRunOnlyWorkflows(ctx context.Context, workflow string, files []*github.CommitFile) bool {
	// Skip the workflow if the committed changes are only for
	// .github/workflows/* and they do not affect the given workflow
	for _, file := range files {
		filename := file.GetFilename()
		if !strings.HasPrefix(filename, ".github/workflows") || filename == `.github/workflows/`+workflow {
			return true
		}

	}
	return false
}

// ShouldRunWorkflow compares given list of files against a workflow's PathsRegex / PathsIgnoreRegex and workflow's filename.
// Return true if any file matches .github/workflows/{workflow} OR .if any file matches PathsRegex
// OR if any file does NOT match PathsIgnoreRegex AND does NOT have .github/workflow prefix
// Return false otherwise.
func (config *ArianeConfig) ShouldRunWorkflow(ctx context.Context, workflow string, files []*github.CommitFile) bool {
	// No new commits, skip re-running workflows
	if len(files) == 0 {
		return false
	}

	workflowConfig, exists := config.Workflows[workflow]
	// No workflow definition for the triggered workflow by a command
	// 	- /command is expected to trigger one or more workflows
	//	- these workflows are expected to be defined under the "workflows:" section
	if !exists {
		return false
	}

	// PathsRegex and PathsIgnoreRegex are both defined - this is UNSUPPORTED!!
	// default to run the workflow no matter what
	if workflowConfig.PathsRegex != "" && workflowConfig.PathsIgnoreRegex != "" {
		return true
	}

	var re, reIgnore *regexp.Regexp
	var err error

	if workflowConfig.PathsRegex != "" {
		if re, err = regexp.Compile(`^` + workflowConfig.PathsRegex); err != nil {
			log.FromContext(ctx).Err(err).Msgf("cannot compile regexp %q", workflowConfig.PathsRegex)
			return false
		}
	}
	if workflowConfig.PathsIgnoreRegex != "" {
		if reIgnore, err = regexp.Compile(`^` + workflowConfig.PathsIgnoreRegex); err != nil {
			log.FromContext(ctx).Err(err).Msgf("cannot compile regexp %q", workflowConfig.PathsIgnoreRegex)
			return false
		}
	}

	numberIgnoredFiles := 0
	for _, file := range files {
		filename := file.GetFilename()
		// Run the workflow if:
		//	Any file under .github/workflows has changed (including the WF itself)
		// 	PathsRegex has a match
		// Note: .github/workflows contains env-vars, dependent workflows (e.g. workflow_call),
		// and other files which may be relevant to the current workflow
		// TODO: Add intelligence to the "workflows" section of Ariane config to determine dependencies
		// (common ones [env-vars] + specific of the workflow [dependent WF])
		// if strings.HasPrefix(filename, ".github/workflows") || re.MatchString(filename) {
		// 	return true
		// }

		// Alternatively, only run the workflow if:
		//	The workflow file has been updated
		//	PathsRegex has a match
		if filename == `.github/workflows/`+workflow || (re != nil && re.MatchString(filename)) {
			return true
		} else if strings.HasPrefix(filename, ".github/workflows") {
			// A change on a different workflow (e.g. bar.yaml) does not qualify to re-run
			// the one we are validating (e.g. foo.yaml)
			numberIgnoredFiles += 1
			continue
		}

		// Flag any finding within PathsIgnoreRegex
		if reIgnore != nil && reIgnore.MatchString(filename) {
			numberIgnoredFiles += 1
		}
	}

	// the workflow (e.g. foo.yaml) does not change
	// PathsRegex exists (no match, or we would have returned immediately),
	// PathIgnoreRegex does not exist
	// expectation: the workflow (e.g. foo.yaml) should not run
	if re != nil && reIgnore == nil {
		return false
	}

	// At this point, we know there are files committed. If all the files match
	// PathsIgnoreRegex (numberIgnoredFiles == len(files)) or other workflows than,
	// the one we are evaluating, then do not run the WF
	// Otherwise, do run it
	return numberIgnoredFiles < len(files)
}

