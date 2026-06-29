# Security Policy

## Reporting a Vulnerability

**Do not file a public GitHub issue for security vulnerabilities.**

Please send a private report to: **security@your-org.example.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Your suggested fix (optional)

We aim to respond within 5 business days and will coordinate a disclosure timeline with you.

## Security Considerations

### What this library does NOT guarantee

- It does not guarantee regulatory compliance (GDPR, HIPAA, CCPA, etc.)
- It does not guarantee 100% PII detection — false negatives are possible
- It does not replace proper data-handling policies and access controls
- It should not be the only security layer protecting sensitive data

### Implemented security controls

- API key authentication with constant-time comparison (`hmac.compare_digest`)
- Mapping IDs are cryptographically random UUID4 hex strings
- TTL-based automatic expiry of Redis mappings
- Raw PII values are never written to application logs
- Error messages never include original text or credentials
- Request size limits to prevent abuse
- Redis persistence disabled by default in Docker Compose
- Containers run as non-root user

### Responsible use

This library helps reduce the exposure of PII to external AI providers. However:

- Always evaluate whether redaction is sufficient for your compliance requirements
- Consider whether the LLM provider's API terms allow your use case
- Apply defence-in-depth: this tool complements, not replaces, other controls
