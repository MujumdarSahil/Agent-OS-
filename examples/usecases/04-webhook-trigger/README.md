# Use Case 04: Webhook Ingress Trigger & Untrusted Payload Labeling

Demonstrates Sub-milestone 2.2 security and execution invariants for webhook triggers:

1. **Benign Ingress**: A cryptographically signed webhook request (`X-AgentOS-Signature`, `X-AgentOS-Timestamp`) against a valid secret path creates an asynchronous run with an `untrusted` security label on its payload, completing successfully via the queue backend.
2. **Unsigned / Bad Signature Ingress**: An unsigned, forged, or mismatched HMAC signature returns an identical `404 Not Found` response with no information disclosure and zero runs created.
3. **Replay Ingress**: A duplicate request re-using a valid signature within the 5-minute replay window is caught by the nonce cache, returning `404 Not Found` and zero runs created.
4. **Adversarial Payload Injection**: An untrusted payload containing prompt injection instructions attempting to exfiltrate data to an external sink is blocked by AgentOS security policy and label contracts.

## Security & Network Considerations

- **Client IP Rate Limiting:** Webhook rate limits are enforced per client IP directly from client connection information. In deployments behind a reverse proxy (such as NGINX, AWS ALB, or Cloudflare), trusted-proxy configuration is required so that client IPs cannot be spoofed via untrusted upstream headers. Explicit trusted-proxy CIDR configuration is a documented Phase 3 known gap.
