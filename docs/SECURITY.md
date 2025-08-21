# SECURITY.md

## Threat Model
- Tool handles untrusted input (targets); validates and sanitizes strings used in subprocess calls.
- PDF/TXT exporters avoid embedding sensitive content unescaped.

## Hardening
- Use non-privileged user.
- Keep OS and network tooling up-to-date.
- Prefer Simulate unless explicitly cleared for Deep Scan.

## Disclosure
Report issues via internal ticketing or repository issues (private).
