# Codebase Concerns

**Analysis Date:** 2026-04-22

## Tech Debt

**Concurrency and Synchronization:**
- Issue: Heavy use of manual `sync.WaitGroup` and `sync.Mutex` for network probes.
- Files: `internal/webcheck/webcheck.go`
- Impact: Code is verbose and error-prone; managing timeouts and context cancellation across many goroutines is difficult to audit.
- Fix approach: Transition to a channel-based or task-queue worker pattern to encapsulate concurrency management and improve readability.

**Hardcoded Configurations:**
- Issue: Critical constants (DNS resolvers, timeout values, retry counts) are hardcoded.
- Files: `internal/webcheck/webcheck.go`
- Impact: Reduces flexibility for different network environments or testing scenarios without recompilation.
- Fix approach: Move configuration to a structure or environment variable loader.

## Security Considerations

**Insecure TLS Configuration:**
- Issue: `InsecureSkipVerify: true` is used across multiple probes.
- Files: `internal/webcheck/webcheck.go`
- Impact: The tool is susceptible to Man-in-the-Middle (MITM) attacks. While the intent is to analyze censorship, this is a significant security risk.
- Recommendations: Implement a custom `VerifyPeerCertificate` function that only ignores specific errors relevant to SNI/domain validation while keeping core TLS security checks intact.

## Performance Bottlenecks

**DNS Resolution:**
- Issue: Sequential DNS resolution across multiple providers is limited by the slowest provider and timeout.
- Files: `internal/webcheck/webcheck.go`
- Impact: Increases diagnosis latency.
- Improvement path: Optimize the asynchronous resolution flow to prioritize faster responses while maintaining control.

## Fragile Areas

**DNS Response Parsing:**
- Issue: Manual parsing of raw DNS responses and reliance on internal `dnsmessage` usage.
- Files: `internal/webcheck/webcheck.go`
- Why fragile: Any deviation in packet structure or unexpected DNS responses could cause parsing errors.
- Safe modification: Consider using a robust, community-vetted DNS library instead of manual `dnsmessage` manipulation.

## Test Coverage Gaps

**Unit Testing:**
- Issue: Limited test coverage for individual probes.
- Files: `internal/webcheck/webcheck_test.go`, `internal/netutil/host_test.go`
- Risk: Changes in network logic (e.g., probe classification) could break core functionality without detection.
- Priority: High. Introduce table-driven tests for DNS, TCP, and HTTP probe logic, specifically mocking network responses to simulate censorship conditions.

---

*Concerns audit: 2026-04-22*
