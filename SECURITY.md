# Security Policy

## Report privately

Do not open a public issue, discussion, or pull request for a suspected
security vulnerability.

Use GitHub's private vulnerability reporting form:

https://github.com/omarespejel/AIRLock/security/advisories/new

Include:

- the affected AIRLock and upstream commits;
- the violated security invariant;
- attacker capabilities and required preconditions;
- the smallest reproducible case and exact commands;
- expected and observed verifier behavior;
- known application impact and important impact not yet demonstrated;
- a proposed fix, if available.

Do not include credentials, private keys, customer data, production witness
material, or unrestricted live endpoints.

## Scope

This policy covers vulnerabilities in AIRLock itself, including false-green
analysis, lossy exports, unsafe parsing, transcript-modeling errors, and report
or artifact integrity failures.

A vulnerability discovered in Stwo, SparseProve, or another downstream or
upstream project should be reported privately to that project's security team.
AIRLock may later retain a synthetic regression that does not disclose an
embargoed construction.

## Coordinated disclosure

Please allow time to reproduce, assess, and coordinate a fix before public
disclosure. AIRLock maintainers will keep reports restricted to the people
needed to review them and will not assign impact beyond the evidence.

The public issue tracker remains appropriate for non-security bugs, false
positives, documentation errors, and feature requests that do not reveal a
private vulnerability.
