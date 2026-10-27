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

## Assessed advisories

CI runs `pip-audit` on every push. The advisories below are suppressed after review because they are not exploitable in this project's configuration:

| Advisory | Package | Affects | Why not exploitable here |
|----------|---------|---------|--------------------------|
| PYSEC-2026-311 (CVE-2026-45829) | chromadb | Pre-auth code injection via the server's `/api/v2/.../collections` endpoint | No ChromaDB server runs; the app uses the embedded `PersistentClient` with no network listener |
| PYSEC-2026-3814 (CVE-2026-45833) | chromadb | Authenticated code injection via the server's collection-update endpoint | Same: no server endpoint exists |
| PYSEC-2026-3815 (CVE-2026-45831) | chromadb | Cross-tenant actions in the server's `SimpleRBACAuthorizationProvider` | No server, no RBAC provider, single local tenant |
| PYSEC-2026-3813 (CVE-2026-45830) | chromadb | Missing tenant authorization in the server API | Same as above |

No patched chromadb release exists yet. **Never run `chroma run` or expose ChromaDB over HTTP with this project's data** while these remain open. Re-check when a fix ships, then remove the ignores from `.github/workflows/ci.yml`.

See the **Security model** section of the README for the defences in place.
