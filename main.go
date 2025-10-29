// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gregjones/httpcache"
	"github.com/palantir/go-githubapp/githubapp"
	"github.com/rs/zerolog"

	"github.com/cilium/ariane/internal/config"
	"github.com/cilium/ariane/internal/handlers"
)

const (
	DefaultHealthRoute = "/healthz"
	DefaultRoute       = "/"
)

func main() {
	serverConfig, err := config.ReadServerConfig(config.ServerConfigPath)

	if err != nil {
		panic(err)
	}

	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
	zerolog.DefaultContextLogger = &logger

	cc, err := githubapp.NewDefaultCachingClientCreator(
		serverConfig.Github,
		githubapp.WithClientUserAgent("cilium-ariane/0.0.1"),
		githubapp.WithClientTimeout(3*time.Second),
		githubapp.WithClientCaching(false, func() httpcache.Cache { return httpcache.NewMemoryCache() }),
	)

	if err != nil {
		panic(err)
	}

	prCommentHandler := &handlers.PRCommentHandler{ClientCreator: cc, RunDelay: serverConfig.RunDelay}
	mergeGroupHandler := &handlers.MergeGroupHandler{ClientCreator: cc}
	webhookHandler := githubapp.NewDefaultEventDispatcher(serverConfig.Github, prCommentHandler, mergeGroupHandler)

	http.Handle(githubapp.DefaultWebhookRoute, webhookHandler)

	// add a health check endpoint
	http.HandleFunc(DefaultHealthRoute, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("OK"))
		if err != nil {
			logger.Error().Err(err).Msg("Failed to write health check response")
		}
	})

	// add a default route
	http.HandleFunc(DefaultRoute, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("Ariane is running!" + "\nVersion: " + serverConfig.Version))
		if err != nil {
			logger.Error().Err(err).Msg("Failed to write default response")
		}
	})

	addr := fmt.Sprintf("%s:%d", serverConfig.Server.Address, serverConfig.Server.Port)
	logger.Info().Msgf("Starting server on %s...", addr)
	err = http.ListenAndServe(addr, nil)
	if err != nil {
		panic(err)
	}
}
