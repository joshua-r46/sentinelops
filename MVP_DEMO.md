# AgentShield local MVP demo

This is a development-only simulation. It creates synthetic evidence and a synthetic diagnosis/policy decision, requires an explicit operator approval, performs no infrastructure action, and labels verification as simulated. The database is a uniquely named SQLite file in the OS temporary directory and is removed when the process exits.

From the project root in PowerShell:

```powershell
$env:AGENTSHIELD_DEMO_MODE = 'development'
Set-Location agentshield
python -m uvicorn mvp_demo:app --host 127.0.0.1 --port 8099
```

Open <http://127.0.0.1:8099/>. Click **Run demonstration**, inspect the test evidence and diagnosis, then explicitly choose **Approve dry-run** or **Deny and escalate**. Repeat the run to show an independent second incident. Do not describe this simulation as attack detection or a real production recovery.

Verify without Docker using the existing task-local virtual environment:

```powershell
& 'C:\Users\Joshua R\Documents\Codex\2026-11-13\referenced-chatgpt-conversation-this-is-an-14\work\stage\shopstack\.venv\Scripts\python.exe' -m unittest discover -s tests -p test_mvp_demo.py -v
```

The full ShopStack, PostgreSQL, Redis, real Safety Gate, Executor and independent Verifier are not started by this demo. Their existing dashboard routes remain separate and report unavailable unless those services are actually reachable.
