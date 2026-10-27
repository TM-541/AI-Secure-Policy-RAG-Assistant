# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Report them privately via GitHub's **Security → Report a vulnerability** (private advisory) on this repository, including:

- a description of the issue and its impact
- steps or a prompt that reproduces it (e.g. a guardrail bypass)
- the commit or version tested

You can expect an acknowledgement within 5 working days.

## Scope

In scope: prompt-injection or system-prompt-leak bypasses, data exfiltration through model output, authentication issues in the admin panel, unsafe file handling during ingestion, and secrets exposure.

Out of scope: issues requiring access to the host machine or its `data/` folder, and attacks on Ollama, ChromaDB or Streamlit themselves (report those upstream).

## Handling secrets

- Secrets live only in `.env`, which is git-ignored. Use `.env.example` as the template.
- Policy documents, databases and audit logs are git-ignored and must never be committed.
- If a secret is committed by mistake, rotate it immediately; removing the commit is not enough.

See the **Security model** section of the README for the defences in place.
