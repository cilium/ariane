// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/palantir/go-githubapp/githubapp"
	"gopkg.in/yaml.v3"
)

const (
	DefaultRunDelay      = 30 * time.Second
	DefaultServerAddress = "127.0.0.1"
	DefaultServerPort    = 8080
	DefaultVersion       = "0.0.1-dirty"
	ServerConfigPath     = "server-config.yaml"
)

type ServerConfig struct {
	Server HTTPConfig       `yaml:"server"`
	Github githubapp.Config `yaml:"github"`
	// RunDelay represents delay between running Commit Status Start job and re-running failed tests
	RunDelay time.Duration `yaml:"runDelay"`
	Version  string        `yaml:"version"`
}

type HTTPConfig struct {
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
}

func ReadServerConfig(path string) (*ServerConfig, error) {
	var c ServerConfig

	// check if the file exists. else use environment variables
	if _, err := os.Stat(path); os.IsNotExist(err) {
		println("Server config file not found, using environment variables")

		c.SetValuesFromEnv("")
		if c.Github.V3APIURL == "" ||
			c.Github.App.WebhookSecret == "" ||
			c.Github.App.PrivateKey == "" ||
			c.Github.App.IntegrationID == 0 {
			return nil, fmt.Errorf("missing required GitHub app configuration: V3APIURL, WebhookSecret, PrivateKey, or IntegrationID")
		}

	} else {
		bytes, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed reading server config file: %w", err)
		}

		if err := yaml.Unmarshal(bytes, &c); err != nil {
			return nil, fmt.Errorf("failed parsing configuration file: %w", err)
		}
	}

	return &c, nil
}

func (s *ServerConfig) SetValuesFromEnv(prefix string) {
	s.Github.SetValuesFromEnv(prefix)

	// sanitize the private key by replacing escaped newlines with actual newlines
	if s.Github.App.PrivateKey != "" {
		s.Github.App.PrivateKey = strings.ReplaceAll(s.Github.App.PrivateKey, "\\n", "\n")
	}

	s.Server.Address = DefaultServerAddress
	if v, ok := os.LookupEnv(prefix + "ARIANE_SERVER_ADDRESS"); ok {
		s.Server.Address = v
	}

	s.Server.Port = DefaultServerPort
	if v, ok := os.LookupEnv(prefix + "ARIANE_SERVER_PORT"); ok {
		port, err := strconv.Atoi(v)
		if err == nil {
			s.Server.Port = port
		}
	}

	s.RunDelay = DefaultRunDelay
	if v, ok := os.LookupEnv(prefix + "ARIANE_RUN_DELAY"); ok {
		delay, err := time.ParseDuration(v)
		if err == nil {
			s.RunDelay = delay
		}
	}

	s.Version = DefaultVersion
	if v, ok := os.LookupEnv(prefix + "ARIANE_VERSION"); ok {
		s.Version = v
	}
}
