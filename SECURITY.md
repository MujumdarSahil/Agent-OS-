# Security Policy

## Permitted Uses

AgentOS cybersecurity tools are designed for:

- ✅ **Defensive Security Operations**: System hardening, configuration auditing, compliance checking
- ✅ **Educational Purposes**: Security awareness, training, research
- ✅ **Security Auditing**: Password policy evaluation, firewall rule validation, permission auditing
- ✅ **Monitoring & Analysis**: Log analysis, anomaly detection, metadata inspection
- ✅ **Compliance**: NIST, OWASP, and industry standard compliance checking

## Explicit Prohibitions

AgentOS **strictly prohibits**:

- ❌ **Exploit Code Generation**: No code that exploits vulnerabilities
- ❌ **Malware Creation**: No trojans, viruses, backdoors, or malicious software
- ❌ **Password Cracking**: No actual password cracking or brute-force attacks
- ❌ **Unauthorized Access**: No attempts to gain unauthorized system access
- ❌ **Active Scanning**: No active network probing or port scanning
- ❌ **System Modification**: No unauthorized changes to system configurations
- ❌ **Privilege Escalation**: No privilege escalation automation

## Safety Guarantees

1. **Governance Enforcement**: All operations pass through Governance Engine checks
2. **Read-Only Operations**: System audit tools only read, never modify
3. **Hash-Only Inputs**: Password tools only accept hashes, never cleartext
4. **Metadata Analysis**: Network monitoring analyzes logs only, no active probing
5. **Pattern Detection**: Scripts are scanned for prohibited patterns before execution
6. **Safety Metadata**: All tool outputs include safety_metadata

## Compliance

- All tools comply with ethical cybersecurity practices
- Designed for defensive security operations
- Suitable for enterprise security teams, SOC operations, and security research
- No offensive security capabilities or attack tools

## Reporting Security Issues

If you discover a security vulnerability, please report it responsibly to the project maintainers.

