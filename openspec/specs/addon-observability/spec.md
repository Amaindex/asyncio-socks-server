# Addon observability specification

## Purpose

`asyncio-socks-server` exposes observability and audit behavior through opt-in addons. Runtime counters, active flow snapshots, closed-flow audit summaries, and HTTP presentation are separate concerns so applications can compose the pieces they need without making the core server heavier.

## Requirements

### Requirement: Flow statistics infrastructure

The system SHALL provide a `FlowStats` addon that collects in-memory runtime counters without starting a network listener.

#### Scenario: FlowStats observes active flows

- GIVEN `FlowStats` is installed in the server addon list
- WHEN a TCP CONNECT or UDP ASSOCIATE flow starts
- THEN the addon records the active flow
- AND `snapshot()` includes active flow counts, active byte totals, total flow counters, and active flow snapshots

#### Scenario: FlowStats records closed flows

- GIVEN `FlowStats` observed a flow
- WHEN that flow closes
- THEN the addon removes it from the active set
- AND retains a bounded recent closed-flow snapshot
- AND updates closed-flow and byte totals

#### Scenario: FlowStats records errors

- GIVEN `FlowStats` receives error hook notifications
- WHEN errors occur
- THEN `errors()` reports a total count, counts by exception type, and bounded recent error records

### Requirement: Usage audit infrastructure

The system SHALL provide a `FlowAudit` addon that aggregates closed-flow usage in memory without starting a network listener.

#### Scenario: Closed-flow audit record

- GIVEN `FlowAudit` is installed in the server addon list
- WHEN a flow closes
- THEN the addon records upload, download, total bytes, source host, target host, protocol, and timestamps
- AND `snapshot()` reports the current in-memory audit window

#### Scenario: Device and destination summaries

- GIVEN multiple closed flows have been recorded
- WHEN an audit snapshot is requested
- THEN the snapshot includes total upload, download, and combined traffic
- AND includes top device and destination summaries sorted by total traffic

#### Scenario: Audit reset

- GIVEN an audit window contains records
- WHEN `reset()` is called
- THEN retained recent records, device summaries, destination summaries, period fields, and totals are cleared

### Requirement: Opt-in HTTP presentation

The system SHALL provide `StatsAPI` as an explicit HTTP presentation addon around `FlowStats` and optional `FlowAudit`.

#### Scenario: StatsAPI owns stats

- GIVEN `StatsAPI` is installed without an external `FlowStats` instance
- WHEN flows and errors occur
- THEN the addon owns an internal `FlowStats`
- AND forwards relevant hooks into that internal collector

#### Scenario: StatsAPI presents external collectors

- GIVEN application code installs `FlowStats`, `FlowAudit`, and `StatsAPI` with references to those collectors
- WHEN flows close and API endpoints are requested
- THEN `StatsAPI` presents the supplied collector state
- AND does not double-count flows already observed by the supplied collectors

#### Scenario: Stats endpoints

- GIVEN `StatsAPI` is running
- WHEN a client requests `/health`, `/stats`, `/flows`, or `/errors`
- THEN the API returns JSON liveness, runtime counters, flow snapshots, or error counters respectively

#### Scenario: Audit endpoints

- GIVEN `StatsAPI` is running with a `FlowAudit` instance
- WHEN a client requests `/audit` or posts to `/audit/refresh`
- THEN the API returns the current audit snapshot
- AND supports bounded top results and optional device filtering

#### Scenario: Audit disabled

- GIVEN `StatsAPI` is running without a `FlowAudit` instance
- WHEN a client requests an audit endpoint
- THEN the API returns an error indicating audit is disabled

### Requirement: Addon order visibility

The system SHALL make addon ordering the application's responsibility.

#### Scenario: Observability before competitive routing

- GIVEN an application needs flow start visibility for stats
- WHEN the addon list includes observability addons and competitive routing addons
- THEN observability addons should appear before routing addons that may win a competitive hook
- AND flow close observers still receive final flow snapshots even if they did not observe the flow start

### Requirement: Backward-compatible stats name

The system SHALL keep `StatsServer` as a backward-compatible public name for `StatsAPI` in the 1.x series.

#### Scenario: Existing StatsServer code

- GIVEN application code imports `StatsServer`
- WHEN it constructs and installs that addon
- THEN it receives the same broad HTTP presentation behavior as `StatsAPI`
- AND new code can use `StatsAPI` to describe the role more precisely
