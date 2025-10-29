// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package log

import (
	"context"

	"github.com/rs/zerolog"
)

type logKey struct{}

func FromContext(ctx context.Context) *zerolog.Logger {
	if l := ctx.Value(logKey{}); l != nil {
		return l.(*zerolog.Logger)
	}
	return nil
}

func WithLogger(ctx context.Context, logger *zerolog.Logger) context.Context {
	return context.WithValue(ctx, logKey{}, logger)
}
