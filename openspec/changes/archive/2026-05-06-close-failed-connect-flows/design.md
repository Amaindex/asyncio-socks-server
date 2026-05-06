## Context

`FlowStats` observes TCP CONNECT starts through the addon `on_connect` hook and
removes flows from its active set through `on_flow_close`. The server core
created the flow and dispatched `on_connect` before opening the direct remote
connection, but remote setup failures returned without dispatching flow close.
That left observability addons with an active flow that no longer had a live
server lifecycle.

The fix belongs in the core lifecycle, not in `FlowStats`, because addons should
not infer failed setup cleanup independently. Once the core exposes a `Flow` to
addons, it owns completing that lifecycle.

## Goals / Non-Goals

**Goals:**

- Complete every observed TCP CONNECT lifecycle with one flow-close notification.
- Preserve the split between core lifecycle guarantees and opt-in observability.
- Avoid new runtime dependencies, persistent state, public endpoints, or addon
  hook signature changes.
- Cover failed remote setup with a regression test.

**Non-Goals:**

- Add idle timeout management for established relay connections.
- Change SOCKS5 reply mapping for setup failures.
- Change `FlowStats` storage model or StatsAPI response shape.
- Add AX deployment-specific cleanup logic to the project.

## Decisions

1. Wrap the observed TCP CONNECT setup and relay path in a `try/finally`.

   Once `dispatch_connect(flow)` has run, the server dispatches
   `dispatch_flow_close(flow)` from `finally`. This makes the lifecycle rule
   independent of whether the direct remote connection succeeds, fails, or the
   addon rejects setup.

   Alternative considered: make `FlowStats` age out zero-byte active flows. That
   would hide one symptom while leaving the core lifecycle contract incomplete.

2. Log relay close details only after a successful CONNECT reply.

   Failed setup already logs the setup error and sends the SOCKS5 failure reply.
   Keeping the detailed `closed ... bytes` log behind a `connected` flag avoids
   making failed setup attempts look like established relays.

3. Keep the change inside existing hooks.

   No new hook is needed. `on_flow_close` already means the flow lifecycle ended,
   and failed setup after observation is still an ended flow.

## Risks / Trade-offs

- Some addons may not have expected close notifications for failed setup flows.
  This is compatible with the documented lifecycle model because the addon
  already observed the flow start; completing it is safer than leaking it.
- The close event for a failed setup carries zero byte counters. That accurately
  describes a flow that never reached relay.

## Migration Plan

Release a patch/minor version containing the core fix and deploy it normally.
Existing long-lived stale active entries in a running process disappear after a
restart because `FlowStats` is in-memory. Rollback is a normal package/image
rollback to the previous release.

## Open Questions

None.
