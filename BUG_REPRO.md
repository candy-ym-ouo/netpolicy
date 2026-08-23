# Bug Reproduction

## Trigger

1. Fill the Worker queue so that a task submission must wait for capacity.
2. Submit an analysis task with an HTTP request context.
3. Cancel the request while the queue is full.

## Observed

The API replaces the request context with `context.Background()` before calling the Worker. Queue waiting therefore continues after the client request has been canceled, and the handler cannot observe the request lifecycle.

## Expected

The original request context should reach the queue wait. Cancellation must release the submission promptly while successful submissions and Worker shutdown retain their existing behavior.
