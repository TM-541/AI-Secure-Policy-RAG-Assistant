# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Local, security-hardened RAG chatbot answering employee questions from company HR policy documents. Stack: Streamlit UI, Ollama (chat + embeddings), ChromaDB (embedded), SQLite (original file bytes + metadata). Nothing is meant to leave the machine.

## Commands

```powershell
streamlit run app.py                         # run the app (needs Ollama running with both models pulled)
python ingest_policies.py                    # import new files from policy_docs/to_import/ and re-index
python ingest_policies.py --list             # stored documents with IDs
python ingest_policies.py --remove 3 7       # delete by ID and re-index

pytest -q                                    # guardrail red-team suite (no Ollama needed)
pytest -q tests/test_guardrails.py -k "attacks_are_blocked"            # one test group
pytest -q "tests/test_guardrails.py::test_policy_questions_are_allowed" # one test

# CI's dependency audit (the ignored IDs are documented in SECURITY.md)
pip-audit -r requirements.txt --ignore-vuln PYSEC-2026-311 --ignore-vuln PYSEC-2026-3813 --ignore-vuln PYSEC-2026-3814 --ignore-vuln PYSEC-2026-3815
```

CI (`.github/workflows/ci.yml`) runs `py_compile` on every module, `pytest`, then `pip-audit`. There is no linter configured.

On Windows, ad-hoc scripts that print answers need `PYTHONIOENCODING=utf-8`: answers contain emoji and the default cp1252 console raises `UnicodeEncodeError`.

## Architecture

**Request path** (`PolicyRAG.ask` in `rag_engine.py`), in this order; each stage can short-circuit:
1. Strip control characters; length check (`MAX_QUESTION_CHARS`).
2. `guardrails.check_input`: rejects any readable Base64/hex blob outright, then scans several decoded/normalised variants of the question (NFKC, zero-width removal, leetspeak, spaced letters, URL-decode, ROT13) against `_PATTERNS` (which includes `config.INJECTION_PATTERNS`). Returns `BLOCKED_ANSWER`.
3. LRU answer cache lookup (key = lowercased, whitespace-collapsed question).
4. Embed + Chroma query. **Relevance gate:** if the nearest chunk's cosine distance > `RELEVANCE_MAX_DISTANCE`, return `REFUSAL_ANSWER` without calling the LLM.
5. LLM call: system prompt built from `SYSTEM_PROMPT_TEMPLATE`; context wrapped in a random per-process tag; `<`/`>` stripped from the question.
6. `LeakDetector.is_leak`: secret canary or ≥2 five-word shingles shared with the system prompt → `BLOCKED_ANSWER`, never cached.
7. `_guard_output`: redact `SENSITIVE_PATTERNS`, strip markdown images/links/URLs (exfiltration channel), flag injection-like text in the retrieved chunks.
8. Audit log, then cache.

`ask()` always returns `(answer, sources, warnings)`. `app.py` relies on this, and on `answer in BLOCKED_ANSWERS`, to throttle a session after `MAX_BLOCKED_PER_SESSION` blocks. Off-topic refusals deliberately do **not** count toward throttling.

**Shared state:** `app.py` creates `PolicyRAG` via `@st.cache_resource`, so a single instance (its answer cache, canary and context tag) is shared by every browser session in the process. Per-user state (admin login, failure counts, throttling) lives in `st.session_state`.

**Indexing:** `rebuild_index()` runs on every app start but is a no-op unless the signature stored in SQLite `app_metadata.index_signature` changes. The signature covers `INDEX_VERSION`, `EMBED_MODEL`, `CHUNK_SIZE`, `CHUNK_OVERLAP` and every document's id+sha256. **Bump `INDEX_VERSION` whenever you change extraction or chunking logic** (e.g. `normalize_text`, `extract_records`), or existing indexes will not rebuild. Documents that fail extraction are skipped and audited rather than failing the whole index. `ingest_policies.py` also runs `extract_records` before storing, so unreadable files (encrypted or scanned PDFs) never enter SQLite.

**Configuration:** everything comes from `.env` through `config.py`, which bounds-checks values with `_env_int`/`_env_float` and silently falls back to the default on bad input. Data lives under `data/` (`policy_store.sqlite3`, `chroma_db/`, `audit.log`). The `chroma_db/` and `policy_store.sqlite3` in the repo root are legacy copies, not read by the code.

## Conventions that matter here

- **Guardrail changes:** add attack strings to `ATTACKS` *and* realistic policy questions to `LEGIT` in `tests/test_guardrails.py`. False positives are the main risk, since phrases like "ignore my manager's instructions" and "act as a line manager" must still pass. Prefer narrow patterns over broad keywords.
- **`RELEVANCE_MAX_DISTANCE` (0.50) was calibrated against `nomic-embed-text`:** policy questions scored 0.20–0.42, off-topic or jailbreak prompts above 0.50. Re-measure if the embedding model changes.
- **Fixed replies:** `REFUSAL_ANSWER` and `NOT_FOUND_ANSWER` are removed from the leak-detector fingerprint because the model is told to emit them verbatim. Keep that exclusion if you add new fixed replies, or legitimate refusals will be flagged as leaks.
- **Audit log:** `write_audit_log(event, user_input, detail)` stores only a truncated SHA-256 of `user_input`. Pass a constant (e.g. `"audit_panel"`) rather than anything secret: a hash of a short password is crackable.
- **HTML rendering:** `app.py` renders with `unsafe_allow_html=True`. Any document- or user-derived string must go through `html.escape`; user messages use `show_user_text`, never raw `st.markdown`.
- **No external requests from the page:** fonts are system stacks (no Google Fonts or CDNs), and Streamlit and ChromaDB telemetry are disabled. `.streamlit/config.toml` binds to `127.0.0.1`.
- **Never run ChromaDB as a server** (`chroma run`, `HttpClient`). The CI-ignored chromadb advisories are only safe because the app uses the embedded `PersistentClient` (see SECURITY.md).
- **Git:** policy PDFs, `.env`, `data/`, databases and logs are git-ignored and must stay that way. `policy_docs/to_import/README.txt` is the only tracked file in that folder, and the importer skips it.
