# Bug Reproduction

## Trigger

1. Create a task that will fail while its result or task state is being persisted.
2. Retry the task through the API.
3. Make the persistence layer return `storage.ErrNotFound` during the retry update.

## Observed

The storage layer formats the persistence error with `%v`, so the wrapped error text still contains the original message but its identity is lost. The API cannot match it with `errors.Is`, and returns `500 INTERNAL` instead of the resource-specific `404 TASK_NOT_FOUND` response.

## Expected

The error should retain its identity while adding operation context. The API should be able to classify it with `errors.Is` and preserve the existing HTTP error mapping.
