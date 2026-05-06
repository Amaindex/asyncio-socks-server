## MODIFIED Requirements

### Requirement: Flow context

The system SHALL create one `Flow` context for each TCP CONNECT or UDP ASSOCIATE lifecycle and pass that context through addon hooks.

#### Scenario: TCP flow lifecycle

- GIVEN a valid TCP CONNECT request
- WHEN the server accepts the request
- THEN the flow records source address, destination address, protocol `tcp`, start time, and byte counters
- AND the same flow object is passed to connect, data, and close hooks for that connection

#### Scenario: TCP setup failure after observation

- GIVEN a valid TCP CONNECT request
- AND the server has dispatched the connect hook with a flow
- WHEN remote connection setup fails before relay starts
- THEN the server sends an appropriate SOCKS5 failure reply
- AND dispatches the flow close hook for the same flow

#### Scenario: UDP flow lifecycle

- GIVEN a valid UDP ASSOCIATE request
- WHEN the server accepts the request
- THEN the flow records source address, destination address, protocol `udp`, start time, and byte counters
- AND the same flow object is passed to UDP associate and close hooks for that association

#### Scenario: Byte counters

- GIVEN data passes through a TCP or UDP relay
- WHEN bytes are forwarded
- THEN relay code updates `Flow.bytes_up` and `Flow.bytes_down`
- AND addons can read those counters without owning the counting logic
