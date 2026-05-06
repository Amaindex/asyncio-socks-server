## 1. Specification

- [x] 1.1 Capture the failed CONNECT lifecycle problem in proposal and design materials
- [x] 1.2 Add spec deltas for core flow lifecycle and observability behavior

## 2. Implementation

- [x] 2.1 Ensure observed TCP CONNECT flows always dispatch flow close on setup failure
- [x] 2.2 Preserve existing SOCKS5 failure replies and established relay logging behavior

## 3. Verification

- [x] 3.1 Add a regression test for failed CONNECT flow cleanup
- [x] 3.2 Run focused server error and stats tests
