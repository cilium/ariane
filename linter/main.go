// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"

	"github.com/cilium/ariane/internal/config"
	"github.com/hmdsefi/gograph"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <ariane-config.yaml> [ariane-config-enterprise.yaml ...]\n", os.Args[0])
		os.Exit(1)
	}

	hasErrors := false
	var configs []*config.ArianeConfig

	for _, path := range os.Args[1:] {
		cfg, err := parseAndValidate(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR [%s]: %v\n", path, err)
			hasErrors = true
			continue
		}
		configs = append(configs, cfg)
		fmt.Printf("OK [%s]: valid ariane config\n", path)
	}

	// If multiple configs provided, validate the merged result as well
	if len(configs) > 1 {
		merged := configs[0]
		for _, c := range configs[1:] {
			merged = merged.Merge(c)
		}
		if errs := validateConfig(merged); len(errs) > 0 {
			fmt.Fprintf(os.Stderr, "ERROR [merged config]:\n")
			for _, err := range errs {
				fmt.Fprintf(os.Stderr, "  - %v\n", err)
			}
			hasErrors = true
		} else {
			fmt.Println("OK [merged config]: valid after merge")
		}
	}

	if hasErrors {
		os.Exit(1)
	}
}

func parseAndValidate(path string) (*config.ArianeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var cfg config.ArianeConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Check for unknown fields by doing a strict unmarshal via a map first
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse YAML as map: %w", err)
	}
	knownTopLevel := map[string]bool{
		"feedback":      true,
		"triggers":      true,
		"workflows":     true,
		"allowed-teams": true,
		"rerun":         true,
		"stages-config": true,
		"schedule":      true,
	}
	for key := range raw {
		if !knownTopLevel[key] {
			return nil, fmt.Errorf("unknown top-level key: %q", key)
		}
	}

	if errs := validateConfig(&cfg); len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "- %v\n", e)
		}
		return nil, fmt.Errorf("validation failed with %d error(s)", len(errs))
	}

	return &cfg, nil
}

func validateConfig(cfg *config.ArianeConfig) []error {
	var errs []error

	// Validate triggers reference existing workflows or at least have entries
	for trigger, triggerCfg := range cfg.Triggers {
		if len(triggerCfg.Workflows) == 0 {
			errs = append(errs, fmt.Errorf("trigger %q has no workflows", trigger))
		}

		// Validate trigger phrase compiles as regex
		if _, err := regexp.Compile(trigger); err != nil {
			errs = append(errs, fmt.Errorf("trigger %q is not a valid regex: %v", trigger, err))
		}

		// Validate depends-on references exist as triggers
		for _, dep := range triggerCfg.DependsOn {
			if _, ok := cfg.Triggers[dep]; !ok {
				errs = append(errs, fmt.Errorf("trigger %q depends on %q, which is not defined as a trigger", trigger, dep))
			}
		}
	}

	// Validate that there are no cycles in trigger dependencies
	graph := gograph.New[string](gograph.Acyclic())
	for trigger, triggerCfg := range cfg.Triggers {
		for _, dep := range triggerCfg.DependsOn {
			_, err := graph.AddEdge(gograph.NewVertex(dep), gograph.NewVertex(trigger))
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to add edge from %q to %q in trigger dependency graph: %v", dep, trigger, err))
			}
		}
	}
	// Validate workflow path regexes compile
	for workflow, wfCfg := range cfg.Workflows {
		if wfCfg.PathsRegex != "" {
			if _, err := regexp.Compile(wfCfg.PathsRegex); err != nil {
				errs = append(errs, fmt.Errorf("workflow %q has invalid paths-regex %q: %v", workflow, wfCfg.PathsRegex, err))
			}
		}
		if wfCfg.PathsIgnoreRegex != "" {
			if _, err := regexp.Compile(wfCfg.PathsIgnoreRegex); err != nil {
				errs = append(errs, fmt.Errorf("workflow %q has invalid paths-ignore-regex %q: %v", workflow, wfCfg.PathsIgnoreRegex, err))
			}
		}
		if wfCfg.PathsRegex != "" && wfCfg.PathsIgnoreRegex != "" {
			errs = append(errs, fmt.Errorf("workflow %q defines both paths-regex and paths-ignore-regex, which is unsupported", workflow))
		}
	}

	// Validate rerun config
	if cfg.RerunConfig != nil {
		if cfg.RerunConfig.MaxRetries < 0 {
			errs = append(errs, fmt.Errorf("rerun max-retries must be non-negative, got %d", cfg.RerunConfig.MaxRetries))
		}
	}

	// Validate stages config
	if cfg.StagesConfig != nil {
		for i, stage := range cfg.StagesConfig.Stages {
			if len(stage.Workflows) == 0 {
				errs = append(errs, fmt.Errorf("stage[%d] has no workflows", i))
			}
			if stage.Command == "" {
				errs = append(errs, fmt.Errorf("stage[%d] has no command", i))
			}
		}
	}

	return errs
}
