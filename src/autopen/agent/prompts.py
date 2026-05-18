"""System prompts and prompt templates for the pentest agent."""

from __future__ import annotations


from autopen.state.models import ScanProfile

# ---------------------------------------------------------------------------
# Phase descriptions
# ---------------------------------------------------------------------------

PHASES = [
    ("1. Reconnaissance",
     "Passive and active information gathering about the target. "
     "Use nmap for port/service discovery. Enumerate hostnames, banners, and OS."),
    ("2. Scanning & Enumeration",
     "Deep enumeration of discovered services. "
     "Web: run nikto, gobuster/ffuf for directory discovery. "
     "Network: enumerate SMB shares, FTP, SNMP, etc."),
    ("3. Vulnerability Assessment",
     "Identify exploitable vulnerabilities. "
     "Use nuclei for known CVEs. Test for SQLi, XSS, default credentials. "
     "Cross-reference service versions against known CVEs."),
    ("4. Exploitation",
     "Attempt to exploit confirmed vulnerabilities to demonstrate impact. "
     "Use sqlmap for SQL injection, hydra for credential attacks, "
     "metasploit for known exploits. Document all successful attacks."),
    ("5. Reporting",
     "Once all phases are complete, call the 'report_done' tool to signal "
     "that the assessment is finished and a report should be generated."),
]

# ---------------------------------------------------------------------------
# Profile-specific guidance
# ---------------------------------------------------------------------------

PROFILE_GUIDANCE: dict[str, str] = {
    ScanProfile.WEB: (
        "Focus on OWASP Top 10: injection flaws, broken authentication, "
        "sensitive data exposure, XXE, broken access control, security misconfigurations, "
        "XSS, insecure deserialization, known vulnerable components, and logging failures."
    ),
    ScanProfile.NETWORK: (
        "Focus on network-layer attacks: open ports with vulnerable services, "
        "unencrypted protocols (Telnet, FTP, HTTP), SMB/RPC vulnerabilities, "
        "default credentials on network devices, and lateral movement opportunities."
    ),
    ScanProfile.CLOUD: (
        "Focus on cloud misconfigurations: publicly accessible storage buckets, "
        "overly permissive IAM roles, exposed metadata endpoints (169.254.169.254), "
        "unencrypted data, default security group rules, and leaked credentials."
    ),
    ScanProfile.CTF: (
        "This is a CTF/lab environment. Prioritize speed and coverage. "
        "Look for flags in web responses, file system, databases, and environment variables. "
        "Try common CTF patterns: hidden directories, LFI/RFI, SSTI, XXE, deserialization."
    ),
}

# ---------------------------------------------------------------------------
# System prompt builder
# ---------------------------------------------------------------------------

REPORT_DONE_TOOL = {
    "name": "report_done",
    "description": (
        "Signal that the penetration test is complete and a final report should be generated. "
        "Call this when you have thoroughly completed all applicable phases."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "description": "Brief assessment summary (2-3 sentences)",
            },
            "key_findings": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of the most critical findings",
            },
        },
        "required": ["summary"],
    },
}


def build_system_prompt(
    target: str,
    profile: str,
    scope_description: str,
    authorization_token: str,
) -> str:
    """Build the master system prompt for the pentest agent."""
    phases_text = "\n".join(f"  {name}: {desc}" for name, desc in PHASES)
    profile_guidance = PROFILE_GUIDANCE.get(profile, "Perform a comprehensive assessment.")

    return f"""You are an expert penetration tester conducting an authorized security assessment.

## Authorization
The following authorization has been provided:
"{authorization_token}"

## Target
{target}

## Authorized Scope
{scope_description}

## Scan Profile: {profile.upper()}
{profile_guidance}

## Methodology (follow in order)
{phases_text}

## Rules of Engagement
1. ONLY target hosts within the authorized scope above.
2. Work systematically through each phase before moving to the next.
3. Use findings from each phase to inform your next actions.
4. When you find something interesting, follow up with deeper investigation.
5. Prefer targeted, efficient tool usage over broad spraying.
6. **Call `record_finding` immediately whenever you discover a vulnerability or noteworthy issue.** Do not wait until the end — record findings as soon as they are confirmed.
7. When all applicable phases are complete, call `report_done` with a summary.
8. If a tool fails or produces no results, briefly note it and move on.

## Output Style
- Think step by step before each tool call.
- After observing results, explicitly state what you found and what it means.
- Prioritize HIGH/CRITICAL severity findings.
"""


def build_initial_user_message(target: str, profile: str) -> str:
    return (
        f"Begin the penetration test against target: {target}\n"
        f"Profile: {profile}\n\n"
        f"Start with Phase 1 (Reconnaissance). Use nmap to enumerate open ports and services."
    )


def build_tool_error_message(tool_name: str, error: str) -> str:
    return f"Tool '{tool_name}' failed with error: {error}\nPlease try an alternative approach."


def build_scope_violation_message(tool_name: str, target: str) -> str:
    return (
        f"SCOPE VIOLATION BLOCKED: Tool '{tool_name}' attempted to target '{target}', "
        f"which is outside the authorized scope. Do not attempt to target this host again."
    )


def build_denial_message(tool_name: str) -> str:
    return (
        f"ACTION DENIED by operator: '{tool_name}' was not approved. "
        f"Continue the assessment without this action, or try a less intrusive approach."
    )
