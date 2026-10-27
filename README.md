# AI Secure Policy RAG Assistant

![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![LLM](https://img.shields.io/badge/LLM-Ollama%20(local)-black) ![Security](https://img.shields.io/badge/security-prompt--injection%20hardened-success)

A local, privacy-first RAG (retrieval-augmented generation) chatbot that answers employee questions from approved company policy documents, with citations. Everything runs on your machine: **Ollama** for the LLM and embeddings, **ChromaDB** for vector search, **SQLite** for document storage, **Streamlit** for the UI.

## Features

- **Grounded answers with citations**: every answer cites the source document and page.
- **Local inference**: no cloud APIs; Streamlit and ChromaDB telemetry disabled, no external fonts or CDNs.
- **Layered prompt-injection defence** (see [Security model](#security-model))
- **Audit logging**: JSON Lines log (SIEM-friendly). Questions are stored as truncated hashes, never plaintext.
- **Admin audit panel**: password from `.env`, constant-time comparison, lockout after repeated failures, failed attempts logged.
- **Efficient**: index rebuilt only when documents or chunk/embedding settings change; repeated questions served from an in-memory cache; models kept warm in Ollama.
- **Safe ingestion**: file type, size and signature checks; encrypted/scanned/unparseable files rejected before storage; symlink and path-escape protection; duplicate content skipped.

## Architecture

```
policy_docs/to_import/  ──ingest_policies.py──▶  data/policy_store.sqlite3  (original files + metadata)
                                                  data/chroma_db/            (chunk embeddings)
                                                           │
Employee ──▶ app.py (Streamlit) ──▶ rag_engine.py ──▶ input guard ─▶ retrieve top-K ─▶ Ollama LLM
                                                  ◀── output guard (redact, strip links) ◀──┘
                                                           │
                                                  data/audit.log  (security events)
```

| File | Purpose |
|------|---------|
| `app.py` | Streamlit UI: chat, citations, system status, admin audit panel |
| `rag_engine.py` | Text extraction, chunking, embeddings, retrieval, generation, output guards, answer cache |
| `guardrails.py` | Input normalisation/decoding, injection patterns, system-prompt leak detection |
| `storage.py` | SQLite document store, metadata, audit log writer/reader |
| `ingest_policies.py` | Admin CLI: import, list and remove policy documents |
| `config.py` | All settings, loaded from `.env` with safe defaults |
| `.streamlit/config.toml` | Hardened Streamlit server settings |

## Setup (Windows / VS Code)

1. Install Ollama from https://ollama.com/download, then pull the models:

   ```powershell
   ollama pull llama3.2:3b
   ollama pull nomic-embed-text
   ```

2. Create a virtual environment and install requirements (Python 3.10+):

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. Create your `.env` from the template and set an admin password:

   ```powershell
   Copy-Item .env.example .env
   python -c "import secrets; print(secrets.token_urlsafe(24))"   # paste as ADMIN_PASSWORD
   ```

## Import policies (administrator)

Place policy files (PDF, DOCX, TXT, MD; max 20 MB each) in `policy_docs/to_import/`, then run:

```powershell
python ingest_policies.py
```

Other admin commands:

```powershell
python ingest_policies.py --list            # show stored documents with their IDs
python ingest_policies.py --remove 3 7      # remove documents by ID and re-index
python ingest_policies.py --folder D:\hr    # import from a different folder
```

Duplicate file contents are skipped. To update a policy, import the new version and `--remove` the old one so outdated rules are not cited.

## Run the assistant

```powershell
streamlit run app.py
```

Open http://localhost:8501. The app loads the stored index automatically and re-indexes only if documents or chunk/embedding settings changed.

By default the server listens on **127.0.0.1 only**. To serve employees on your network:

```powershell
streamlit run app.py --server.address 0.0.0.0
```

Only do this behind HTTPS (reverse proxy) and network access controls; Streamlit itself has no user authentication.

## Configuration

All settings live in `.env` (see `.env.example`):

| Variable | Default | Notes |
|----------|---------|-------|
| `ADMIN_PASSWORD` | *(empty)* | Empty keeps the audit panel locked |
| `ADMIN_MAX_ATTEMPTS` | `5` | Failed logins per session before lockout |
| `OLLAMA_HOST` | `http://127.0.0.1:11434` | A remote host means data leaves the machine; the UI shows a warning |
| `OLLAMA_TIMEOUT` | `180` | Seconds |
| `CHAT_MODEL` | `llama3.2:3b` | Any Ollama chat model |
| `EMBED_MODEL` | `nomic-embed-text` | Changing it triggers a re-index |
| `TOP_K` | `4` | Chunks retrieved per question |
| `CHUNK_SIZE` / `CHUNK_OVERLAP` | `1000` / `150` | Changing them triggers a re-index |
| `MAX_ANSWER_TOKENS` | `300` | Answer length cap |
| `ANSWER_CACHE_SIZE` | `128` | `0` disables the cache |
| `MODEL_KEEP_ALIVE` | `30m` | How long Ollama keeps models loaded |
| `RELEVANCE_MAX_DISTANCE` | `0.50` | Off-topic cut-off; recalibrate if you change `EMBED_MODEL` |
| `MAX_BLOCKED_PER_SESSION` | `3` | Blocked requests before the chat pauses |
| `BLOCK_COOLDOWN_SECONDS` | `300` | Length of that pause |

## Security model

A small local model cannot be trusted to keep secrets or refuse reliably on its own, so each request passes through independent layers. An attack has to beat all of them:

| # | Layer | Stops |
|---|-------|-------|
| 1 | **Input normalisation**: Unicode NFKC, zero-width characters removed, leetspeak, spaced-out letters, URL encoding, ROT13, Base64 and hex decoded before scanning | Obfuscated payloads (`1gn0r3`, `i g n o r e`, full-width text, `SGVsbG8...`) |
| 2 | **Injection scanner**: instruction overrides, system-prompt extraction, role-play/jailbreak personas, fake chat-template tags, encode/decode/translate tricks. Any readable encoded blob is rejected outright | Direct prompt injection and prompt leaking |
| 3 | **Relevance gate**: questions far from every policy chunk are refused before the LLM runs | Off-topic abuse, jailbreak role-play, and wasted GPU time |
| 4 | **Hardened prompt**: fixed refusal replies, explicit no-transform/no-persona rules; context wrapped in a random per-process tag; `<` `>` stripped from the question | Context-boundary forgery; indirect injection from documents |
| 5 | **Leak detector**: secret canary token plus phrase-overlap fingerprint of the instructions; matching answers are withheld | System prompt disclosure even when the model is fooled |
| 6 | **Output sanitiser**: redacts SSNs, card numbers, keys and secrets; strips images, links and URLs | PII leakage; markdown-image data exfiltration |
| 7 | **Session throttling and audit**: 3 blocked attempts pause the chat for 5 minutes; every block, leak, off-topic request and throttle is logged | Automated probing; gives investigators a trail |

Additional controls: user and document text are HTML-escaped before rendering; the admin panel uses constant-time comparison with lockout; the server binds to localhost with telemetry off.

**Limits:** pattern-based defences reduce risk but cannot be complete; a determined attacker may find new phrasings. Throttling is per browser session, so it slows probing but does not stop someone who reopens the page; the audit log is the durable record. Treat any answer as guidance and verify against the original policy.

## Security notes

- `.env`, `data/`, databases, logs and the policy documents themselves are excluded by `.gitignore`. Never commit them.
- The admin password protects only the audit panel. Restrict access to the machine and the `data/` folder, especially if policies contain salary or personal data.
- Scanned PDFs have no text layer and are rejected; run OCR first.

## Testing

The guardrail red-team suite runs without Ollama:

```powershell
pip install -r requirements-dev.txt
pytest -q
pip-audit -r requirements.txt      # check dependencies for known CVEs
```

GitHub Actions runs the same checks on every push and pull request (`.github/workflows/ci.yml`), and Dependabot opens weekly dependency-update PRs.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| "The policy assistant could not start" | Make sure Ollama is running (`ollama list`) and both models are pulled |
| "No policy documents are stored in SQLite" | Run `python ingest_policies.py` |
| A file is skipped during import | Check the printed reason: encrypted, scanned, too large or wrong signature |
| Audit panel says "locked" | Set `ADMIN_PASSWORD` in `.env` and restart Streamlit |
