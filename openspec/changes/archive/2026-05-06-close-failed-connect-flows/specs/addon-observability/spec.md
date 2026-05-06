## MODIFIED Requirements

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

#### Scenario: FlowStats clears failed TCP setup flows

- GIVEN `FlowStats` observed a TCP CONNECT flow
- WHEN remote connection setup fails and the core closes the flow
- THEN `snapshot()` reports no active entry for that failed flow
- AND closed-flow counters include the failed setup lifecycle

#### Scenario: FlowStats records errors

- GIVEN `FlowStats` receives error hook notifications
- WHEN errors occur
- THEN `errors()` reports a total count, counts by exception type, and bounded recent error records
