# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities through GitHub private vulnerability
reporting on this repository. Please do not open a public issue for security
reports.

Include steps to reproduce and the impact you observed. Expect an
acknowledgement within a few business days.

## Scope

This is a stdlib-only Python package that scans the local machine for
installed software and writes an SBOM (CycloneDX or SPDX). It stores no
credentials and makes no network calls by default; an optional upload step
for drift/CVE comparison is opt-in and documented in the README.
