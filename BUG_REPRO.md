# Bug Reproduction

## Trigger

1. Create an asynchronous analysis task with a `policySets` filter.
2. Allow the Worker to load the persisted task parameters.
3. Compare the rules used by the asynchronous analysis with the same filter in synchronous analysis.

## Observed

The API persists the filter under `policySets`, while the Worker still reads `_policySets`. The filter is therefore absent at execution time and rules outside the requested policy set participate in the analysis.

## Expected

The API, persisted task parameters, and Worker should use one compatible field contract. The selected policy set must constrain asynchronous analysis without changing task state or result formatting.
