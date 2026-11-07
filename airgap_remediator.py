#!/usr/bin/env python3
"""
AirGap Remediator - Autonomous Air-Gapped Security Scanner & Remediation Agent.
Single-command CLI & entrypoint for scanning, remediation, pipeline orchestration, and web UI.
"""

from agents.git_agent.cli import main

if __name__ == "__main__":
    main()

