"""Security auditing agent using openai-agents."""
import json
import os
import subprocess
import tempfile
from typing import Dict, List

from agents import Agent, tool


def find_requirements(root: str = ".") -> List[str]:
    """Locate requirement or setup files in the project."""
    requirement_files: List[str] = []
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            lower = name.lower()
            if lower == "requirements.txt" or lower.endswith("requirements.txt") or lower == "setup.py":
                requirement_files.append(os.path.join(dirpath, name))
    return requirement_files


# Functions that can be wrapped as tools
def pip_audit(requirement_file: str) -> Dict:
    """Run pip-audit for the given requirements file."""
    result = subprocess.run(
        ["pip-audit", "-r", requirement_file, "-f", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.stdout:
    if result.returncode != 0:
        # Optionally log the error, e.g. print(result.stderr)
        return {}
    if result.stdout:
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            # Optionally log the error, e.g. print("Failed to parse pip-audit output as JSON")
            return {}
    return {}


def bandit_scan(path: str = ".") -> Dict:
    """Execute bandit security scan for the repository."""
    result = subprocess.run(
        ["bandit", "-r", path, "-f", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.stdout:
    if result.returncode != 0:
        print(f"Bandit scan failed with return code {result.returncode}. stderr: {result.stderr}")
        return {}
    if result.stdout:
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as e:
            print(f"Failed to parse Bandit JSON output: {e}")
            return {}
    return {}


def query_custom_api(package: str) -> Dict:
    """Mocked custom vulnerability API."""
    # Placeholder returning no vulnerabilities.
    return {"package": package, "vulnerabilities": []}


def consolidate(findings: Dict) -> str:
    """Write findings to a temporary JSON file and return its path."""
    fd, tmp_path = tempfile.mkstemp(prefix="security_findings_", suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(findings, f, indent=2)
    return tmp_path


def apply_non_breaking_fixes(findings: Dict) -> None:
    """Placeholder for applying non-breaking fixes."""
    # In a full implementation, versions would be upgraded here.
    pass


def commit_changes(message: str = "Apply security fixes") -> None:
    """Commit changes using Git."""
    subprocess.run(["git", "commit", "-am", message], check=False)


def main() -> None:
    """Run the security agent."""
    req_files = find_requirements()
    pip_audit_tool = tool.function_tool()(pip_audit)
    bandit_tool = tool.function_tool()(bandit_scan)
    custom_tool = tool.function_tool()(query_custom_api)
    agent = Agent(name="security-agent", tools=[pip_audit_tool, bandit_tool, custom_tool])

    audit_results = {path: pip_audit(path) for path in req_files}
    bandit_results = bandit_scan(".")

    packages = {
        line.split("==")[0].split(">=")[0]
        for req in req_files
        for line in open(req).read().splitlines()
        if line.strip() and not line.startswith("#")
    packages = set()
    for req in req_files:
        try:
            with open(req) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        packages.add(line.split("==")[0].split(">=")[0])
        except (OSError, IOError) as e:
            print(f"Warning: Could not read {req}: {e}")
    custom_results = {pkg: query_custom_api(pkg) for pkg in packages}

    findings = {
        "pip_audit": audit_results,
        "bandit": bandit_results,
        "custom": custom_results,
    }

    findings_path = consolidate(findings)
    apply_non_breaking_fixes(findings)
    commit_changes()
    print(f"Findings written to {findings_path}")


if __name__ == "__main__":
    main()
