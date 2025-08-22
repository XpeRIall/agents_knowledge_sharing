#!/usr/bin/env python3
"""Security auditing agent using openai-agents."""
import argparse
import asyncio
import glob
import os
import requests
import json
import subprocess
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Dict, List, Optional, Any

from agents import Agent, Runner
from agents.tool import FunctionTool

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

os.environ["OPENAI_LOG"] = "debug"                # OpenAI client debug logs
os.environ["AGENTS_LOG_LEVEL"] = "debug"

# ----------------------------
# OSV helpers
# ----------------------------

def _normalize_osv_vuln(v: Dict[str, Any]) -> Dict[str, Any]:
    """Pick commonly useful fields from an OSV vulnerability item."""
    severities = []
    if "severity" in v and isinstance(v["severity"], list):
        for s in v["severity"]:
            t = s.get("type")
            sc = s.get("score")
            if t or sc:
                severities.append({"type": t, "score": sc})

    return {
        "id": v.get("id"),
        "modified": v.get("modified"),
        "published": v.get("published"),
        "withdrawn": v.get("withdrawn"),
        "summary": v.get("summary"),
        "details": v.get("details"),
        "aliases": v.get("aliases", []),
        "affected": v.get("affected", []),
        "severity": severities,
        "references": v.get("references", []),
    }

def query_osv(package: str, version: Optional[str] = None) -> Dict[str, Any]:
    """
    Query OSV for vulnerabilities affecting a PyPI package.
    If version is omitted, try to resolve installed version.
    """
    resolved_version: Optional[str] = version
    if resolved_version is None:
        try:
            resolved_version = importlib_metadata.version(package)
        except importlib_metadata.PackageNotFoundError:
            return {
                "package": package,
                "version": None,
                "vulnerabilities": [],
                "error": ("Package not installed; provide a version "
                          "to query OSV accurately (e.g., version='1.2.3')."),
            }

    payload = {
        "package": {"ecosystem": "PyPI", "name": package},
        "version": resolved_version,
    }

    try:
        resp = requests.post(OSV_QUERY_URL, json=payload, timeout=15)
        resp.raise_for_status()
        data = resp.json() or {}
        vulns = [_normalize_osv_vuln(v) for v in data.get("vulns", [])]
        return {"package": package, "version": resolved_version, "vulnerabilities": vulns}
    except requests.RequestException as e:
        return {"package": package, "version": resolved_version, "vulnerabilities": [], "error": f"OSV request failed: {e}"}
    except ValueError as e:
        return {"package": package, "version": resolved_version, "vulnerabilities": [], "error": f"OSV response parse error: {e}"}

# ----------------------------
# Core actions
# ----------------------------

def pip_audit(requirement_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Run pip-audit. If requirement_file is provided, audit that file.
    Otherwise, audit the current environment.
    """
    cmd: List[str] = ["pip-audit", "-f", "json"]
    if requirement_file:
        cmd += ["-r", requirement_file]

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)

    # pip-audit may return non-zero even when it prints JSON (findings). Try to parse anyway.
    try:
        if result.stdout and result.stdout.strip():
            return json.loads(result.stdout)
    except json.JSONDecodeError:
        pass
    return {}

def bandit_scan(path: str = ".") -> Dict[str, Any]:
    """Execute bandit security scan for the repository at `path`."""
    result = subprocess.run(
        ["bandit", "-r", path, "-f", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        if result.stdout and result.stdout.strip():
            return json.loads(result.stdout)
    except json.JSONDecodeError:
        pass
    return {}

def find_dependency_files(root: str = ".") -> Dict[str, List[str]]:
    """Find dependency manifests under the given root path."""
    patterns = [
        "**/requirements*.txt",
        "**/Pipfile", "**/Pipfile.lock",
        "**/poetry.lock",
        "**/pyproject.toml",
    ]
    found: List[str] = []
    for pat in patterns:
        found.extend(glob.glob(os.path.join(root, pat), recursive=True))
    # Deduplicate & normalize paths
    norm = sorted({str(Path(p).resolve()) for p in found})
    return {"files": norm}

def apply_non_breaking_fixes(findings: Dict[str, Any]) -> Dict[str, Any]:
    """Placeholder for applying non-breaking fixes. Return a summary for logging."""
    return {"changed_files": [], "notes": "No automatic fixes applied (placeholder)"}

def commit_changes(message: str = "Apply security fixes") -> Dict[str, Any]:
    """Commit changes using Git, handling 'nothing to commit' gracefully."""
    subprocess.run(["git", "add", "-A"], check=False)
    commit = subprocess.run(["git", "commit", "-m", message], capture_output=True, text=True, check=False)
    return {"returncode": commit.returncode, "stdout": commit.stdout, "stderr": commit.stderr}

# ----------------------------
# Adapter wrappers for FunctionTool
#   Your agents version calls on_invoke_tool(ctx, args)
# ----------------------------

def _wrap_find_dependency_files(_ctx, args: Dict[str, Any]):
    return find_dependency_files(args.get("root", "."))
def _coerce_args(args: Any) -> Dict[str, Any]:
    """Accept dict or JSON string; return a dict."""
    if isinstance(args, dict):
        return args
    if isinstance(args, str):
        s = args.strip()
        if not s:
            return {}
        try:
            return json.loads(s)
        except Exception:
            # As a last resort, treat it as a single unnamed value
            return {"__raw": s}
    # handle None / other types
    return {}

# Keep _coerce_args as-is, then make all wrappers async:

async def _wrap_find_dependency_files(_ctx, args: Any):
    a = _coerce_args(args)
    return await asyncio.to_thread(find_dependency_files, a.get("root", "."))

async def _wrap_pip_audit(_ctx, args: Any):
    a = _coerce_args(args)
    req = a.get("requirement_file")
    if not req:
        return {"error": "requirement_file is mandatory"}
    out = await asyncio.to_thread(pip_audit, req)
    print("DEBUG pip_audit for", req, "->", json.dumps(out)[:800], "...")
    return out

async def _wrap_bandit_scan(_ctx, args: Any):
    a = _coerce_args(args)
    return await asyncio.to_thread(bandit_scan, a.get("path", "."))

async def _wrap_query_osv(_ctx, args: Any):
    a = _coerce_args(args)
    # requests.post is blocking → offload
    return await asyncio.to_thread(query_osv, a["package"], a.get("version"))

async def _wrap_apply_non_breaking_fixes(_ctx, args: Any):
    a = _coerce_args(args)
    raw = a.get("security_violations_json", "{}")
    try:
        findings = json.loads(raw)
    except Exception:
        findings = {}
    return await asyncio.to_thread(apply_non_breaking_fixes, findings)

async def _wrap_commit_changes(_ctx, args: Any):
    a = _coerce_args(args)
    return await asyncio.to_thread(commit_changes, a.get("message", "Apply security fixes"))


# ----------------------------
# Main
# ----------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Security auditing agent")
    parser.add_argument(
        "--project-path",
        type=str,
        default=".",
        help="Path to the project to audit (default: current directory)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="security_findings/findings.json",
        help="Where the LLM should write consolidated JSON findings (advised)."
    )
    args = parser.parse_args()

    project_root = str(Path(args.project_path).resolve())

    find_files_tool = FunctionTool(
        name="find_dependency_files",
        description="Find Python dependency manifests (requirements, Pipfile, poetry.lock, pyproject.toml).",
        on_invoke_tool=_wrap_find_dependency_files,
        params_json_schema={
            "type": "object",
            "properties": {
                "root": {"type": "string", "description": "Root directory to search", "default": project_root}
            }
        }
    )

    pip_audit_tool = FunctionTool(
        name="pip_audit",
        description="Audit Python dependencies for known vulnerabilities in a specific requirements file.",
        on_invoke_tool=_wrap_pip_audit,
        params_json_schema={
            "type": "object",
            "properties": {
                "requirement_file": {"type": "string", "description": "Absolute path to a requirements file."}
            },
            "required": ["requirement_file"]
        }
    )

    bandit_tool = FunctionTool(
        name="bandit_scan",
        description="Run bandit security scan on the codebase.",
        on_invoke_tool=_wrap_bandit_scan,
        params_json_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to scan.", "default": project_root}
            }
        }
    )

    query_osv_tool = FunctionTool(
        name="query_osv",
        description="Query OSV (Open Source Vulnerabilities) for a PyPI package/version.",
        on_invoke_tool=_wrap_query_osv,
        params_json_schema={
            "type": "object",
            "properties": {
                "package": {"type": "string", "description": "Package name (PyPI)."},
                "version": {"type": "string", "description": "Specific version to check (optional)."}
            },
            "required": ["package"]
        }
    )

    apply_fixes_tool = FunctionTool(
        name="apply_non_breaking_fixes",
        description="Apply non-breaking version bumps (placeholder).",
        on_invoke_tool=_wrap_apply_non_breaking_fixes,
        params_json_schema={
            "type": "object",
            "properties": {
                "security_violations_json": {
                    "type": "string",
                    "description": "Consolidated findings object as a JSON string."
                }
            },
            "required": ["security_violations_json"]
        }
    )

    commit_tool = FunctionTool(
        name="commit_changes",
        description="Commit changes to the repository (safe if nothing to commit).",
        on_invoke_tool=_wrap_commit_changes,
        params_json_schema={
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "Commit message.", "default": "Apply security fixes"}
            }
        }
    )

    agent = Agent(
        name="security-agent",
        tools=[find_files_tool, pip_audit_tool, bandit_tool, query_osv_tool, apply_fixes_tool, commit_tool],
        instructions=f"""
            You are a security auditor for Python codebases.

            You MUST:

            1) Call `find_dependency_files(root=PROJECT_ROOT)` to list dependency manifests.
            Use ONLY the returned absolute paths; do not invent paths.

            2) For EACH file path ending with 'requirements*.txt', call:
            `pip_audit(requirement_file=<that exact absolute path>)`.
            Do not skip or summarize before running.
            If no such files are found, you may skip pip-audit.

            3) Run `bandit_scan(path=PROJECT_ROOT)` once to check the codebase.

            4) For EVERY vulnerable package reported by pip-audit, call:
            `query_osv(package=..., version=...)` to enrich with OSV data.

            5) Consolidate all results into a single JSON object with keys:
            {{
                "manifests": ...,
                "pip_audit": ...,
                "bandit": ...,
                "osv": ...
            }}

            6) Write the consolidated JSON object to '{args.output}'.

            7) Optionally, call `apply_non_breaking_fixes(security_violations_json=...)` with the consolidated JSON,
            then `commit_changes(message=...)` to commit the changes.

            8) Finally, return the output path and a brief summary of what was found.

            ⚠️ Do not invent results — always use the tool outputs directly.
        """,
    )

    prompt = f"""
Find files with Python dependencies in "{project_root}" and audit them for security vulnerabilities.

Variables:
- PROJECT_ROOT="{project_root}"
- OUTPUT_PATH="{args.output}"
"""

    result = Runner.run_sync(agent, prompt)
    print("Agent run completed. Result:")
    print(result)

if __name__ == "__main__":
    main()
