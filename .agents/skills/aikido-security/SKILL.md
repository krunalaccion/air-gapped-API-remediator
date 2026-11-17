---
name: aikido-security
description: >-
  C#/.NET-focused reference and workflow guide for Aikido Security scanning,
  testing, runtime protection, and remediation capabilities across C# source
  code, dependencies, APIs, and running applications.
---

# Aikido Security – C# Scanning, Testing & Protection Capabilities

Use this skill when designing, integrating, configuring, or evaluating security
scanning, vulnerability remediation, CI/CD security gates, or runtime protection
workflows for **C# / .NET** applications using **Aikido Security**.

---

## 1. C# / .NET Scope

Aikido Security covers the C# application lifecycle across:
- **C# source code**
- **Third-party & open-source dependencies (e.g., NuGet packages)**
- **C# APIs (REST & GraphQL)**
- **Running C# / ASP.NET applications**

---

## 2. C#-Related Security Scanning Capabilities

| Capability | Scope & Purpose |
| :--- | :--- |
| **SAST (Static Application Security Testing)** | Identifies C# source-code vulnerabilities such as SQL Injection, XSS, and insecure coding practices. |
| **SCA (Software Composition Analysis)** | Detects known vulnerabilities in third-party and open-source C#/.NET dependencies, including direct and transitive dependencies. |
| **Secrets Detection** | Identifies exposed API keys, passwords, access tokens, certificates, and encryption keys in C# codebases and configuration files. |
| **DAST (Dynamic Application Security Testing)** | Tests running C# web applications for security vulnerabilities through simulated attacks. |
| **API Security Scanning** | Discovers and tests C# API endpoints for security vulnerabilities, including REST and GraphQL APIs. |
| **Open-Source License Scanning** | Identifies open-source license types and potential license compliance risks across C# dependencies. |
| **Malware Detection** | Identifies potentially malicious open-source packages and software supply-chain threats. |
| **End-of-Life (EOL) Software Detection** | Identifies outdated and unsupported C# / .NET frameworks, runtimes, and software components. |

---

## 3. Additional C# Testing & Protection Capabilities

### 3.1 AI-Powered Penetration Testing
- Performs automated security testing using AI-driven agents to identify and validate exploitable vulnerabilities in running C# applications and APIs.
- Useful for verifying whether detected findings are genuinely exploitable in practice.

### 3.2 Runtime Protection
- Provides in-application protection against certain attacks, including injection attacks.
- Supports API rate limiting to mitigate abuse and automated attacks on exposed C# API endpoints.

---

## 4. Supporting Security Features

- **SBOM Generation**: Generates a Software Bill of Materials containing C#/.NET software components and dependencies for supply-chain visibility and compliance.
- **Vulnerability Prioritization**: Helps prioritize C# findings based on risk and exploitability so teams focus on high-impact issues first.
- **AI AutoTriage**: Assists in analyzing findings and reducing false positives.
- **AI AutoFix**: Provides automated remediation for supported C# vulnerability categories.
- **CI/CD Integration**: Integrates security checks into C# build and deployment pipelines to catch issues before release.
- **On-Premises Scanning**: Supports running code scanners within an organization's own infrastructure (ideal for air-gapped or restricted environments).

---

## 5. Applying This Skill in C# Workflows

When reviewing or implementing security workflows for C# projects:
1. **Shift-Left & Pipeline Checks**: Combine **SAST**, **SCA**, **Secrets Detection**, **Open-Source License Scanning**, **Malware Detection**, and **EOL Software Detection** in **CI/CD Integration** or **On-Premises Scanning** setups.
2. **Live & API Verification**: Pair **DAST**, **API Security Scanning** (REST/GraphQL), and **AI-Powered Penetration Testing** with **Runtime Protection** for running C# services.
3. **Triage & Remediation**: Leverage **Vulnerability Prioritization**, **AI AutoTriage**, **AI AutoFix**, and **SBOM Generation** to streamline remediation and compliance reporting.
