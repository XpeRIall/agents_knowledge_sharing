#!/usr/bin/env python3
"""
Security auditing pipeline (fast + robust).

- Finds dependency manifests
- Runs pip-audit per requirements file
- Runs bandit once
- Queries OSV in a single batch
- Writes a consolidated findings JSON

Default: run locally (no LLM) for speed/reliability.
Optional: --use-agent wraps the whole pipeline in a single tool.
"""

import argparse
import ast
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List

import requests

# Optional agent support (only when --use-agent)
try:
    from agents import Agent, Runner
    from agents.tool import FunctionTool
except Exception:  # pragma: no cover
    Agent = Runner = FunctionTool = None  # type: ignore

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


# ----------------------------
# Helpers
# ----------------------------

def _run(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)

def _coerce_args(args: Any) -> Dict[str, Any]:
    """Agents sometimes pass a JSON string instead of a dict."""
    if isinstance(args, dict):
        return args
    if isinstance(args, str):
        s = args.strip()
        if not s:
            return {}
        try:
            return json.loads(s)
        except Exception:
            # last resort: not JSON, ignore
            return {}
    return {}

def write_json(path: str, obj: Any) -> Dict[str, Any]:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(obj, ensure_ascii=False, indent=2)
    p.write_text(payload, encoding="utf-8")
    return {"path": str(p.resolve()), "bytes": len(payload)}


# ----------------------------
# Steps
# ----------------------------

def find_dependency_files(project_root: str) -> List[str]:
    root = Path(project_root).resolve()
    patterns = [
        "requirements*.txt",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "pyproject.toml",
    ]
    found: List[str] = []
    for pat in patterns:
        found.extend([str(p.resolve()) for p in root.rglob(pat)])
    # dedupe + sort
    return sorted(dict.fromkeys(found))

def run_pip_audit(requirements_file: str) -> Dict[str, Any]:
    cp = _run(["pip-audit", "-f", "json", "-r", requirements_file])
    try:
        if cp.stdout.strip():
            return json.loads(cp.stdout)
    except json.JSONDecodeError:
        pass
    return {}

def run_bandit(project_root: str) -> Dict[str, Any]:
    exclude = ["*.venv*", "venv", "env", "site-packages", "node_modules", "build", "dist", ".git", "__pycache__"]
    cp = _run(["bandit", "-r", project_root, "-f", "json", "-x", ",".join(exclude)])
    try:
        if cp.stdout.strip():
            return json.loads(cp.stdout)
    except json.JSONDecodeError:
        pass
    return {}

def query_osv_batch(pairs: List[Dict[str, str]]) -> Dict[str, Any]:
    if not pairs:
        return {"results": []}
    payload = {
        "queries": [
            {"package": {"ecosystem": "PyPI", "name": p["package"]}, "version": p["version"]}
            for p in pairs
        ]
    }
    resp = requests.post(OSV_BATCH_URL, json=payload, timeout=20)
    resp.raise_for_status()
    data = resp.json() or {}
    out = []
    for (p, r) in zip(pairs, data.get("results", [])):
        out.append({
            "package": p["package"],
            "version": p["version"],
            "vulnerabilities": r.get("vulns", []),
        })
    return {"results": out}


def apply_security_fixes(findings_path: str) -> Dict[str, Any]:
    """Apply security fixes to requirements files based on audit findings."""
    try:
        # Read findings
        with open(findings_path, 'r') as f:
            findings = json.load(f)
        
        fixes_applied = []
        errors = []
        
        # Process each pip audit report
        for pip_report in findings.get("pip_audit", []):
            req_file = pip_report.get("file")
            if not req_file or not Path(req_file).exists():
                continue
                
            # Extract vulnerable packages and their fix versions
            vulnerable_packages = {}
            for dep in pip_report.get("report", {}).get("dependencies", []):
                name = dep.get("name")
                vulns = dep.get("vulns", [])
                
                if name and vulns:
                    # Find minimum safe version from all vulnerabilities
                    fix_versions = []
                    for vuln in vulns:
                        fix_versions.extend(vuln.get("fix_versions", []))
                    
                    if fix_versions:
                        # Use the minimum fix version (most conservative)
                        safe_version = min(fix_versions)
                        vulnerable_packages[name] = safe_version
            
            if not vulnerable_packages:
                continue
                
            # Update requirements file
            try:
                with open(req_file, 'r') as f:
                    lines = f.readlines()
                
                updated_lines = []
                for line in lines:
                    updated_line = line
                    for pkg_name, safe_version in vulnerable_packages.items():
                        # Case-insensitive regex to match package name at start of line
                        import re
                        pattern = rf'^{re.escape(pkg_name)}[=<>!]'
                        if re.match(pattern, line.strip(), re.IGNORECASE):
                            updated_line = f"{pkg_name}>={safe_version}\n"
                            fixes_applied.append({
                                "file": req_file,
                                "package": pkg_name,
                                "safe_version": safe_version
                            })
                            break
                    updated_lines.append(updated_line)
                
                # Write back updated file
                with open(req_file, 'w') as f:
                    f.writelines(updated_lines)
                    
            except Exception as e:
                errors.append(f"Failed to update {req_file}: {str(e)}")
        
        return {
            "fixes_applied": fixes_applied,
            "errors": errors,
            "total_fixes": len(fixes_applied)
        }
        
    except Exception as e:
        return {"error": f"Failed to apply fixes: {str(e)}"}


def apply_bandit_fixes(findings_path: str) -> Dict[str, Any]:
    """Apply intelligent code fixes for Bandit security issues using agent analysis."""
    try:
        # Read findings
        with open(findings_path, 'r') as f:
            findings = json.load(f)
        
        bandit_results = findings.get("bandit", {}).get("results", [])
        if not bandit_results:
            return {"fixes_applied": [], "errors": [], "total_fixes": 0}
        
        fixes_applied = []
        errors = []
        
        # Group issues by file for efficient processing
        issues_by_file = {}
        for issue in bandit_results:
            filename = issue.get("filename")
            if filename and Path(filename).exists():
                if filename not in issues_by_file:
                    issues_by_file[filename] = []
                issues_by_file[filename].append(issue)
        
        # Process each file using agent intelligence
        for filename, file_issues in issues_by_file.items():
            try:
                fix_result = _fix_file_with_agent_analysis(filename, file_issues)
                if fix_result["fixes_applied"]:
                    fixes_applied.append({
                        "file": filename,
                        "fixes": fix_result["fixes_applied"]
                    })
                if fix_result["errors"]:
                    errors.extend(fix_result["errors"])
                    
            except Exception as e:
                errors.append(f"Failed to process {filename}: {str(e)}")
        
        return {
            "fixes_applied": fixes_applied,
            "errors": errors,
            "total_fixes": sum(len(fix["fixes"]) for fix in fixes_applied)
        }
        
    except Exception as e:
        return {"error": f"Failed to apply bandit fixes: {str(e)}"}


def _fix_file_with_agent_analysis(filename: str, issues: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Let agent analyze and fix security issues intelligently."""
    try:
        if Agent is None:
            return {"fixes_applied": [], "errors": ["Agent framework not available"]}
            
        # Read the file
        with open(filename, 'r', encoding='utf-8') as f:
            file_content = f.read()
        
        # Prepare comprehensive prompt for the agent
        issues_summary = []
        for issue in issues:
            issues_summary.append(f"Line {issue.get('line_number', 0)}: {issue.get('test_id', 'unknown')} - {issue.get('issue_text', '')}")
        
        # Create a file-level security fix agent
        security_agent = Agent(
            name="file-security-fixer",
            instructions="""You are a security expert that fixes Python files with multiple vulnerabilities.

You will be given:
1. The complete source code of a Python file
2. A list of security issues found by Bandit static analysis

Your task:
1. Analyze each security issue and understand what needs to be fixed
2. Apply appropriate security fixes to the code
3. Preserve the original functionality while making the code secure
4. Use secure alternatives (secrets instead of random, hashlib.sha256 instead of md5, etc.)
5. For hardcoded secrets, replace with environment variable access
6. For dangerous functions like eval/exec, comment them out with explanations

Return the complete fixed Python file content. Make sure the code is syntactically correct and functional."""
        )
        
        prompt = f"""Please fix the following Python file that has security vulnerabilities:

SECURITY ISSUES FOUND:
{chr(10).join(issues_summary)}

ORIGINAL FILE CONTENT:
```python
{file_content}
```

Please return the complete fixed file content with all security issues addressed."""

        # Use the existing agent execution from the main pipeline
        # This will be handled by the async wrapper in run_with_agent
        import asyncio
        
        try:
            result = asyncio.run(_run_file_fix_agent_async(security_agent, prompt))
            
            if hasattr(result, 'final_output') and result.final_output:
                fixed_content = result.final_output.strip()
                
                # Remove markdown code block markers if present
                if fixed_content.startswith('```python'):
                    fixed_content = fixed_content[9:]
                if fixed_content.endswith('```'):
                    fixed_content = fixed_content[:-3]
                fixed_content = fixed_content.strip()
                
                # Validate that it's actually different
                if fixed_content and fixed_content != file_content:
                    # Write the fixed content
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(fixed_content)
                    
                    return {
                        "fixes_applied": [{
                            "file": filename,
                            "description": f"Applied {len(issues)} security fixes using agent analysis",
                            "issues_fixed": len(issues)
                        }],
                        "errors": []
                    }
            
            return {"fixes_applied": [], "errors": ["Agent did not generate valid fixes"]}
            
        except Exception as e:
            return {"fixes_applied": [], "errors": [f"Agent execution failed: {str(e)}"]}
        
    except Exception as e:
        return {"fixes_applied": [], "errors": [f"File analysis failed: {str(e)}"]}


async def _run_file_fix_agent_async(agent, prompt):
    """Helper to run file fix agent in async context."""
    return await Runner.run(agent, prompt)


def create_security_pr(findings_path: str) -> Dict[str, Any]:
    """Create a pull request with security fixes using agent-generated content."""
    try:
        if Agent is None:
            return {"error": "Agent framework not available for PR creation"}
        
        # Read findings and get git status
        findings_data = _read_findings_and_git_status(findings_path)
        if "error" in findings_data:
            return findings_data
        
        # Generate PR content using agent
        pr_content = _generate_pr_content_with_agent(findings_data)
        if "error" in pr_content:
            return pr_content
        
        # Create branch and commit
        return _create_git_branch_and_commit(pr_content)
        
    except Exception as e:
        return {"error": f"Failed to create PR: {str(e)}"}


def _read_findings_and_git_status(findings_path: str) -> Dict[str, Any]:
    """Read findings file and get git status."""
    try:
        with open(findings_path, 'r') as f:
            findings = json.load(f)
        
        # Count the issues
        dependency_count = sum(
            len(d.get("vulns", []))
            for pr in findings.get("pip_audit", [])
            for d in pr.get("report", {}).get("dependencies", [])
        )
        bandit_count = len(findings.get("bandit", {}).get("results", []))
        
        # Get git status
        result = _run(["git", "status", "--porcelain"])
        changed_files = []
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    changed_files.append(line[3:].strip())
        
        return {
            "dependency_count": dependency_count,
            "bandit_count": bandit_count,
            "changed_files": changed_files,
            "findings": findings
        }
    except Exception as e:
        return {"error": f"Failed to read findings: {str(e)}"}


def _generate_pr_content_with_agent(findings_data: Dict[str, Any]) -> Dict[str, Any]:
    """Generate PR content using agent."""
    try:
        pr_agent = Agent(
            name="pr-generator",
            instructions="""Generate JSON with commit_message, pr_title, and pr_description for security fixes."""
        )
        
        context = f"""Security fixes: {findings_data['dependency_count']} deps + {findings_data['bandit_count']} code issues"""
        
        import asyncio
        pr_result = asyncio.run(_run_pr_agent_async(pr_agent, context))
        
        if hasattr(pr_result, 'final_output') and pr_result.final_output:
            try:
                return json.loads(pr_result.final_output.strip())
            except json.JSONDecodeError:
                pass
        
        # Fallback content
        total_issues = findings_data['dependency_count'] + findings_data['bandit_count']
        return {
            "commit_message": f"fix: resolve {total_issues} security vulnerabilities",
            "pr_title": f"Security fixes: {total_issues} vulnerabilities resolved",
            "pr_description": f"Automated security fixes:\n- Dependencies: {findings_data['dependency_count']}\n- Code issues: {findings_data['bandit_count']}"
        }
    except Exception as e:
        return {"error": f"Failed to generate PR content: {str(e)}"}


def _create_git_branch_and_commit(pr_content: Dict[str, Any]) -> Dict[str, Any]:
    """Create git branch and commit changes."""
    try:
        branch_name = "security-fixes-" + str(int(__import__('time').time()))
        
        # Create branch, add, commit, push
        commands = [
            (["git", "checkout", "-b", branch_name], "create branch"),
            (["git", "add", "."], "add changes"),
            (["git", "commit", "-m", pr_content["commit_message"]], "commit"),
            (["git", "push", "-u", "origin", branch_name], "push branch")
        ]
        
        for cmd, desc in commands:
            result = _run(cmd)
            if result.returncode != 0:
                return {"error": f"Failed to {desc}: {result.stderr}"}
        
        # Now create the actual PR on GitHub
        pr_result = _create_github_pr(branch_name, pr_content)
        
        if "error" in pr_result:
            return {
                "branch_name": branch_name,
                "commit_message": pr_content["commit_message"],
                "pr_title": pr_content["pr_title"],
                "pr_description": pr_content["pr_description"],
                "warning": pr_result["error"],
                "next_steps": f"Branch created successfully. Create PR manually or install GitHub CLI: gh pr create --title \"{pr_content['pr_title']}\" --body \"{pr_content['pr_description']}\""
            }
        
        return {
            "branch_name": branch_name,
            "commit_message": pr_content["commit_message"],
            "pr_title": pr_content["pr_title"],
            "pr_description": pr_content["pr_description"],
            "pr_url": pr_result.get("pr_url"),
            "pr_number": pr_result.get("pr_number"),
            "status": "PR created successfully!"
        }
    except Exception as e:
        return {"error": f"Git operations failed: {str(e)}"}


def _create_github_pr(branch_name: str, pr_content: Dict[str, Any]) -> Dict[str, Any]:
    """Create GitHub PR using GitHub API."""
    try:
        # Extract repository info
        repo_info = _get_github_repo_info()
        if "error" in repo_info:
            return repo_info
        
        # Get GitHub token
        import os
        github_token = os.getenv("GITHUB_TOKEN")
        if not github_token:
            return {"error": "GITHUB_TOKEN environment variable not set. Set it with: export GITHUB_TOKEN=your_token"}
        
        # Create PR via API
        return _make_github_api_request(repo_info, branch_name, pr_content, github_token)
        
    except Exception as e:
        return {"error": f"Failed to create GitHub PR: {str(e)}"}


def _get_github_repo_info() -> Dict[str, Any]:
    """Extract GitHub repository owner and name from git remote."""
    result = _run(["git", "remote", "get-url", "origin"])
    if result.returncode != 0:
        return {"error": "Could not get git remote URL"}
    
    remote_url = result.stdout.strip()
    
    if "github.com" not in remote_url:
        return {"error": "Not a GitHub repository"}
    
    # Handle both SSH and HTTPS URLs
    if remote_url.startswith("git@github.com:"):
        repo_part = remote_url.replace("git@github.com:", "").replace(".git", "")
    elif remote_url.startswith("https://github.com/"):
        repo_part = remote_url.replace("https://github.com/", "").replace(".git", "")
    else:
        return {"error": "Unknown GitHub URL format"}
    
    if "/" not in repo_part:
        return {"error": "Could not parse owner/repo from URL"}
    
    owner, repo = repo_part.split("/", 1)
    return {"owner": owner, "repo": repo}


def _make_github_api_request(repo_info: Dict[str, Any], branch_name: str, pr_content: Dict[str, Any], token: str) -> Dict[str, Any]:
    """Make the actual GitHub API request to create PR."""
    pr_data = {
        "title": pr_content["pr_title"],
        "body": pr_content["pr_description"],
        "head": branch_name,
        "base": "main"
    }
    
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "SecurityAgent/1.0"
    }
    
    import requests
    api_url = f"https://api.github.com/repos/{repo_info['owner']}/{repo_info['repo']}/pulls"
    response = requests.post(api_url, json=pr_data, headers=headers, timeout=30)
    
    if response.status_code == 201:
        pr_info = response.json()
        return {
            "pr_url": pr_info["html_url"],
            "pr_number": pr_info["number"]
        }
    else:
        error_msg = f"GitHub API error {response.status_code}"
        if response.text:
            try:
                error_data = response.json()
                error_msg += f": {error_data.get('message', 'Unknown error')}"
            except json.JSONDecodeError:
                error_msg += f": {response.text[:200]}"
        return {"error": error_msg}


async def _run_pr_agent_async(agent, prompt):
    """Helper to run PR generation agent in async context."""
    return await Runner.run(agent, prompt)


# ----------------------------
# Pipeline
# ----------------------------

def run_audit_pipeline(project_root: str, output_path: str) -> Dict[str, Any]:
    project_root = str(Path(project_root).resolve())

    manifests = find_dependency_files(project_root)

    req_files = [
        p for p in manifests
        if Path(p).name.startswith("requirements") and p.endswith(".txt")
    ]

    pip_reports: List[Dict[str, Any]] = []
    for req in req_files:
        rep = run_pip_audit(req)
        pip_reports.append({"file": req, "report": rep})

    bandit = run_bandit(project_root)

    pairs: List[Dict[str, str]] = []
    for item in pip_reports:
        deps = item.get("report", {}).get("dependencies", [])
        for dep in deps:
            name = dep.get("name")
            ver = dep.get("version")
            vulns = dep.get("vulns", [])
            if name and ver and vulns:
                pairs.append({"package": name, "version": ver})

    # dedupe pairs
    seen = set()
    uniq_pairs: List[Dict[str, str]] = []
    for pr in pairs:
        key = (pr["package"], pr["version"])
        if key not in seen:
            seen.add(key)
            uniq_pairs.append(pr)

    osv = query_osv_batch(uniq_pairs)

    consolidated = {
        "manifests": manifests,
        "pip_audit": pip_reports,  # [{"file":..., "report": {...}}, ...]
        "bandit": bandit,
        "osv": osv,
    }
    out = write_json(output_path, consolidated)

    dep_vuln_count = sum(
        len(d.get("vulns", []))
        for pr in pip_reports
        for d in pr.get("report", {}).get("dependencies", [])
    )
    bandit_count = (
        len(bandit.get("results", []))
        if isinstance(bandit.get("results"), list) else 0
    )

    return {
        "output_path": out["path"],
        "requirements_files": req_files,
        "dependency_vuln_count": dep_vuln_count,
        "bandit_issue_count": bandit_count,
        "osv_results_count": len(osv.get("results", [])),
    }


# ----------------------------
# Optional: openai-agents single tool
# ----------------------------

async def _wrap_run_pipeline(_ctx, args: Any):
    a = _coerce_args(args)
    project_root = a["project_root"]
    output_path = a["output_path"]
    import asyncio
    return await asyncio.to_thread(run_audit_pipeline, project_root, output_path)

async def _wrap_apply_fixes(_ctx, args: Any):
    a = _coerce_args(args)
    findings_path = a["findings_path"]
    import asyncio
    return await asyncio.to_thread(apply_security_fixes, findings_path)

async def _wrap_apply_bandit_fixes(_ctx, args: Any):
    a = _coerce_args(args)
    findings_path = a["findings_path"]
    import asyncio
    return await asyncio.to_thread(apply_bandit_fixes, findings_path)

async def _wrap_create_pr(_ctx, args: Any):
    a = _coerce_args(args)
    findings_path = a["findings_path"]
    import asyncio
    return await asyncio.to_thread(create_security_pr, findings_path)

def run_with_agent(project_root: str, output_path: str) -> Dict[str, Any]:
    if Agent is None or Runner is None or FunctionTool is None:
        raise RuntimeError("openai-agents not available; run without --use-agent")

    run_pipeline_tool = FunctionTool(
        name="run_audit_pipeline",
        description="Run the full security audit and write consolidated JSON.",
        on_invoke_tool=_wrap_run_pipeline,
        params_json_schema={
            "type": "object",
            "properties": {
                "project_root": {"type": "string"},
                "output_path": {"type": "string"},
            },
            "required": ["project_root", "output_path"]
        },
    )

    apply_fixes_tool = FunctionTool(
        name="apply_security_fixes",
        description="Apply security fixes to requirements files based on audit findings.",
        on_invoke_tool=_wrap_apply_fixes,
        params_json_schema={
            "type": "object",
            "properties": {
                "findings_path": {"type": "string"},
            },
            "required": ["findings_path"]
        },
    )

    apply_bandit_fixes_tool = FunctionTool(
        name="apply_bandit_fixes",
        description="Apply code fixes for Bandit security issues in Python files.",
        on_invoke_tool=_wrap_apply_bandit_fixes,
        params_json_schema={
            "type": "object",
            "properties": {
                "findings_path": {"type": "string"},
            },
            "required": ["findings_path"]
        },
    )

    create_pr_tool = FunctionTool(
        name="create_security_pr",
        description="Create a pull request with security fixes and agent-generated commit message and description.",
        on_invoke_tool=_wrap_create_pr,
        params_json_schema={
            "type": "object",
            "properties": {
                "findings_path": {"type": "string"},
            },
            "required": ["findings_path"]
        },
    )

    agent = Agent(
        name="security-agent",
        tools=[run_pipeline_tool, apply_fixes_tool, apply_bandit_fixes_tool, create_pr_tool],
        instructions="First call run_audit_pipeline(project_root=PROJECT_ROOT, output_path=OUTPUT_PATH) to audit, then if vulnerabilities are found, call apply_security_fixes(findings_path=OUTPUT_PATH) to fix dependency issues, call apply_bandit_fixes(findings_path=OUTPUT_PATH) to fix code security issues, and finally call create_security_pr(findings_path=OUTPUT_PATH) to create a pull request with the fixes.",
    )

    prompt = json.dumps({"PROJECT_ROOT": project_root, "OUTPUT_PATH": output_path})
    result = Runner.run_sync(agent, prompt)
    
    # Extract the final output from the RunResult for pretty printing
    if hasattr(result, 'final_output') and result.final_output:
        return {"result": result.final_output}
    else:
        return {"result": str(result)}


# ----------------------------
# CLI
# ----------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Security auditing pipeline")
    ap.add_argument("--project-path", default=".", help="Path to the project root")
    ap.add_argument("--output", default="security_findings/findings.json", help="Where to write consolidated JSON")
    ap.add_argument("--create-pr", action="store_true", help="Create a pull request with the security fixes")
    args = ap.parse_args()

    project_root = str(Path(args.project_path).resolve())
    output_path = str(Path(args.output).resolve())

    if args.create_pr:
        # Enhanced mode with PR creation
        res = run_with_agent(project_root, output_path)
        print("Agent run completed with PR creation.")
    else:
        # Original mode without PR creation
        res = run_with_agent(project_root, output_path)
        print("Agent run completed.")
    
    print("=" * 50)
    print(res["result"])
    print("=" * 50)


if __name__ == "__main__":
    main()
