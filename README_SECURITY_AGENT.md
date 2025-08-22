# Security Agent - Automated Security Vulnerability Detection and Fixing

This security agent provides comprehensive automated security auditing and fixing for Python projects using AI-powered analysis.

## Features

### 🔍 **Security Auditing**
- **Dependency vulnerability scanning** using `pip-audit`
- **Static code analysis** using `Bandit` 
- **OSV database integration** for comprehensive vulnerability data
- **Consolidated JSON reporting** of all findings

### 🛠️ **Automated Fixing**
- **Dependency fixes**: Automatically updates vulnerable packages to safe versions
- **Code security fixes**: AI-powered fixes for code vulnerabilities including:
  - Hardcoded secrets → Environment variables
  - Weak cryptography (MD5/SHA1) → SHA256
  - Insecure random → `secrets` module
  - Dangerous eval/exec → Disabled with comments
  - Pickle vulnerabilities → Disabled with warnings
  - Shell injection → Secure subprocess alternatives
  - Insecure temp files → Safe temp file handling
  - TLS verification issues → Enabled verification
  - YAML loading → Safe loading
  - And many more...

### 🚀 **GitHub Integration**
- **Automatic branch creation** with timestamp-based naming
- **AI-generated commit messages** following conventional commit format
- **Pull Request creation** via GitHub API
- **Professional PR descriptions** explaining all fixes applied

## Usage

### Basic Security Audit and Fix
```bash
python security_agent.py --project-path ./your_project
```

### With Pull Request Creation
```bash
# Set up GitHub token first
export GITHUB_TOKEN=your_github_personal_access_token

# Run with PR creation
python security_agent.py --project-path ./your_project --create-pr
```

### GitHub Token Setup
1. Go to [GitHub Settings → Tokens](https://github.com/settings/tokens)
2. Create a "Personal Access Token" with `repo` permissions
3. Export it: `export GITHUB_TOKEN=your_token_here`

## Example Output

### Security Fixes Applied
The agent successfully identifies and fixes vulnerabilities like:

**Before (Vulnerable):**
```python
# Hardcoded secrets
DB_PASSWORD = "P@ssw0rd!"
AWS_ACCESS_KEY = "AKIAEXAMPLE1234567890"

# Weak crypto
return hashlib.md5(password.encode()).hexdigest()

# Insecure random
return "".join(str(random.random()) for _ in range(5))

# Dangerous eval
return eval(user_input)

# Shell injection
os.system("cat " + user_input)
```

**After (Fixed):**
```python
# Environment variables
DB_PASSWORD = os.getenv("DB_PASSWORD")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY")

# Strong crypto
return hashlib.sha256(password.encode()).hexdigest()

# Secure random
return secrets.token_hex(16)

# Disabled dangerous functions
# return eval(user_input)  # DISABLED: eval() is dangerous
return "Eval functionality disabled for security."

# Secure subprocess
result = subprocess.run(["cat", user_input], check=True, capture_output=True, text=True)
```

### Automated Git Workflow
1. **Scans** your project for vulnerabilities
2. **Applies** intelligent fixes to all issues found
3. **Creates** a new branch (e.g., `security-fixes-1755834861`)
4. **Commits** with AI-generated message (e.g., "fix: resolve 29 security vulnerabilities")
5. **Pushes** branch to GitHub
6. **Creates** Pull Request with detailed description

## Architecture

### Core Components
- **Pipeline Engine**: Orchestrates the entire security workflow
- **Vulnerability Detection**: pip-audit + Bandit + OSV integration
- **AI Fix Generator**: Uses OpenAI agents to intelligently fix security issues
- **Git Integration**: Automated branch/commit/PR creation
- **GitHub API**: Seamless PR creation with professional descriptions

### AI-Powered Fixing
Instead of hardcoded fix patterns, the agent uses LLM analysis to:
- **Understand** each specific vulnerability in context
- **Generate** appropriate fixes that maintain functionality
- **Apply** security best practices automatically
- **Preserve** code readability and structure

## Dependencies
- `pip-audit` - Dependency vulnerability scanning
- `bandit` - Python code security analysis
- `openai-agents` - LLM-powered intelligent fixing
- `requests` - GitHub API integration
- Standard Python libraries (subprocess, json, pathlib, etc.)

## Example Run
```
$ python security_agent.py --project-path ./my_project --create-pr

Agent run completed with PR creation.
==================================================
🔒 Security Audit Complete!

📊 **Findings Summary:**
  • Dependency vulnerabilities: 7 found, 2 fixed
  • Code security issues: 22 found, 22 fixed
  • Total issues resolved: 24

🛠️ **Fixes Applied:**
  • Updated Django: 1.11.29 → 2.2.24
  • Updated Flask: 0.12 → 0.12.3
  • Fixed hardcoded secrets (3 instances)
  • Replaced weak crypto (MD5/SHA1 → SHA256)
  • Secured random generation
  • Disabled dangerous eval/exec
  • Fixed shell injection vulnerabilities
  • And 15 more security improvements...

🚀 **GitHub Integration:**
  • Branch created: security-fixes-1755834861
  • Commit: "fix: resolve 24 security vulnerabilities"
  • Pull Request: #47 - Security fixes: 24 vulnerabilities resolved
  • URL: https://github.com/owner/repo/pull/47

✅ All security issues have been automatically fixed and submitted for review!
==================================================
```

This security agent transforms manual security reviews into a fully automated, AI-powered workflow that not only finds vulnerabilities but intelligently fixes them while maintaining code quality and functionality.
