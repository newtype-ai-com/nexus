package core

import (
	"context"
	"errors"
)

// Providers opt in with a typed classification, never by exposing error bodies.
func isContextOverflow(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var classified interface{ ContextOverflow() bool }
	return errors.As(err, &classified) && classified.ContextOverflow()
}

// The provider rejected our local estimate. Reduce against the actual request,
// not the configured window. Avoid a summary call to the same rejecting model.
func reduceRejectedContext(ctx context.Context, request ModelRequest, current int) (ModelRequest, int, bool) {
	before := RequestTokens(request)
	maxTokens := request.MaxTokens
	request.MaxTokens = max(1, maxTokens*3/4-1000)
	suffix := len(request.Messages) - current
	request, _ = PrepareMessages(ctx, nil, request, current, max(1, before*3/4)+request.MaxTokens+4096)
	current = len(request.Messages) - suffix
	return request, current, RequestTokens(request) < before || request.MaxTokens < maxTokens
}
