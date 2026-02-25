// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/gregjones/httpcache"
	"github.com/palantir/go-githubapp/githubapp"
	"github.com/rcrowley/go-metrics"
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
	metricsRegistry := metrics.DefaultRegistry

	cc, err := githubapp.NewDefaultCachingClientCreator(
		serverConfig.Github,
		githubapp.WithClientUserAgent("cilium-ariane/0.0.1"),
		githubapp.WithClientTimeout(serverConfig.Client.Timeout),
		githubapp.WithClientCaching(false, func() httpcache.Cache { return httpcache.NewMemoryCache() }),
		githubapp.WithClientMiddleware(
			githubapp.ClientMetrics(metricsRegistry),
			githubapp.ClientLogging(zerolog.DebugLevel),
		),
	)

	if err != nil {
		panic(err)
	}

	prCommentHandler := &handlers.PRCommentHandler{
		ClientCreator:    cc,
		RunDelay:         serverConfig.Client.RunDelay,
		MaxRetryAttempts: serverConfig.Client.MaxRetryAttempts,
	}
	mergeGroupHandler := &handlers.MergeGroupHandler{ClientCreator: cc}
	workflowRunHandler := &handlers.WorkflowRunHandler{ClientCreator: cc}
	pullRequestHandler := &handlers.PullRequestHandler{
		ClientCreator:    cc,
		RunDelay:         serverConfig.Client.RunDelay,
		MaxRetryAttempts: serverConfig.Client.MaxRetryAttempts,
	}

	// Use AsyncScheduler to process webhooks asynchronously
	// This allows the handler to respond with an acknowledgment immediately
	// and process the webhook in the background
	asyncScheduler := githubapp.AsyncScheduler(
		githubapp.WithAsyncErrorCallback(func(ctx context.Context, dispatch githubapp.Dispatch, err error) {
			logger := zerolog.Ctx(ctx)
			logger.Error().
				Err(err).
				Str("event_type", dispatch.EventType).
				Str("delivery_id", dispatch.DeliveryID).
				Msg("Error processing webhook asynchronously")
		}),
	)

	webhookHandler := githubapp.NewEventDispatcher(
		[]githubapp.EventHandler{prCommentHandler, mergeGroupHandler, workflowRunHandler, pullRequestHandler},
		serverConfig.Github.App.WebhookSecret,
		githubapp.WithScheduler(asyncScheduler),
	)

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
