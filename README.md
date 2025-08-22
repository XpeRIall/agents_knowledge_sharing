# agents_knowledge_sharing

Prototype project providing a security auditing agent built with
[openai-agents](https://pypi.org/project/openai-agents/).
The agent locates requirement files, runs `pip-audit` and `bandit`,
queries a mocked vulnerability API, aggregates findings into a temporary
JSON file, and prepares a commit with non-breaking fixes.

## Usage

```bash
pip install -r requirements.txt
python security_agent.py
```
