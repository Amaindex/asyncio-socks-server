# SOCKS5 framework specification

## Purpose

`asyncio-socks-server` is a SOCKS5 toolchain for Python applications that need a programmable proxy server. The core provides protocol handling, relay, lifecycle management, and addon hook dispatch. Policy, routing, observability, and optional presentation APIs are composed as addons.

## Requirements

### Requirement: SOCKS5 server core

The system SHALL provide a SOCKS5 server that supports TCP CONNECT and UDP ASSOCIATE while keeping the protocol core independent from policy-specific behavior.

#### Scenario: Direct TCP proxy

- GIVEN a server started without routing addons
- WHEN a SOCKS5 client sends a valid TCP CONNECT request
- THEN the server connects directly to the requested target
- AND bidirectional bytes are relayed until either side closes

#### Scenario: Direct UDP associate

- GIVEN a server started without UDP routing addons
- WHEN a SOCKS5 client sends a valid UDP ASSOCIATE request
- THEN the server provides a UDP relay endpoint
- AND UDP payload bytes are relayed between the client and target

#### Scenario: Unsupported operations

- GIVEN a SOCKS5 client sends an unsupported command or malformed request
- WHEN the server parses the request
- THEN the server rejects the operation with a SOCKS5 error reply or closes the connection according to protocol state

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

### Requirement: Programmable addon dispatch

The system SHALL expose optional async addon hooks with dispatch semantics that match the hook purpose.

#### Scenario: Competitive hooks

- GIVEN multiple addons implement authentication, TCP routing, or UDP routing hooks
- WHEN the corresponding hook is dispatched
- THEN the first non-`None` result wins
- AND later addons for that competitive decision are skipped

#### Scenario: Pipeline data hook

- GIVEN multiple addons implement the data hook
- WHEN a data chunk is relayed
- THEN each addon receives the previous addon's output
- AND returning `None` drops the current chunk and stops the pipeline for that chunk

#### Scenario: Observational hooks

- GIVEN multiple addons implement lifecycle, flow-close, or error hooks
- WHEN the corresponding event occurs
- THEN all applicable addons are called
- AND exceptions in flow-close and error observers do not prevent later observers from running

### Requirement: Chain routing through addons

The system SHALL support chain proxying through addon composition instead of hard-coding chain behavior into the server core.

#### Scenario: TCP chain routing

- GIVEN a `ChainRouter` addon is installed
- WHEN a TCP CONNECT request is accepted
- THEN the addon may open a connection to a downstream SOCKS5 server
- AND the core relays through the returned connection

#### Scenario: UDP-over-TCP chain routing

- GIVEN a `UdpOverTcpEntry` addon is installed at the SOCKS-facing node
- AND a `UdpOverTcpExitServer` runs at the exit node
- WHEN a UDP ASSOCIATE request sends UDP datagrams
- THEN the entry addon encapsulates datagrams into TCP frames
- AND the exit server decapsulates them back to UDP at the target edge

### Requirement: Public compatibility surface

The system SHALL keep the package root as the primary 1.x compatibility surface.

#### Scenario: Stable root imports

- GIVEN application code imports public types from `asyncio_socks_server`
- WHEN the package is upgraded within the 1.x series
- THEN root export names keep their broad behavior
- AND addon hook signatures remain compatible within the documented 1.x contract

#### Scenario: CLI direct server

- GIVEN a user starts the CLI entry point
- WHEN host, port, auth, and log-level options are provided
- THEN the CLI starts a direct SOCKS5 server with optional single-user authentication
- AND advanced routing remains configured through Python composition rather than CLI-only configuration
