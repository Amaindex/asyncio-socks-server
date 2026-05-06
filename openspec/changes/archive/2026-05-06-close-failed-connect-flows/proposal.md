## Why

Observed TCP CONNECT attempts can remain in `FlowStats` active flow snapshots after
remote connection setup fails. This makes long-running deployments report stale
active flows for hours even though the flow lifecycle has already ended.

## What Changes

- Ensure TCP CONNECT flows observed by addons always receive a close notification
  after the connect hook runs, including remote setup failures and addon rejections.
- Keep failed setup attempts out of long-lived active observability state.
- Add regression coverage for failed CONNECT lifecycle accounting.
- No public API names, addon hook signatures, runtime dependencies, or listener
  behavior change.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `socks5-framework`: clarify that observed TCP CONNECT flows are closed even
  when remote connection setup fails before relay starts.
- `addon-observability`: clarify that `FlowStats` removes failed CONNECT flows
  from the active set once the core closes the observed flow.

## Impact

- Affected code: TCP CONNECT lifecycle handling in the server core.
- Affected tests: server error handling and stats lifecycle regression coverage.
- Public compatibility: compatible within the 1.x public API and addon hook
  contract; addons receive an additional close event that completes an already
  observed lifecycle.
