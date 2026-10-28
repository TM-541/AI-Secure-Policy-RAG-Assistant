import hmac
import html
import time
from io import BytesIO
from pathlib import Path
from zipfile import is_zipfile

import streamlit as st
from config import (
    OLLAMA_MODEL, TOP_K, ADMIN_PASSWORD, ADMIN_MAX_ATTEMPTS, OLLAMA_IS_LOCAL,
    MAX_BLOCKED_PER_SESSION, BLOCK_COOLDOWN_SECONDS, MAX_UPLOAD_BYTES,
)
from rag_engine import PolicyRAG, BLOCKED_ANSWERS, extract_records
from storage import init_db, import_document, list_documents, read_audit_tail, write_audit_log

st.set_page_config(
    page_title="Secure Policy Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
    <style>
    :root {
        --bg: #0B1120;
        --panel: #111827;
        --panel-2: #0F172A;
        --border: #1E293B;
        --border-strong: #334155;
        --text: #E5E7EB;
        --text-muted: #94A3B8;
        --accent: #22D3EE;
        --accent-soft: rgba(34, 211, 238, 0.12);
        --ai: #A78BFA;
        --ai-soft: rgba(167, 139, 250, 0.12);
        --ok: #34D399;
        --ok-soft: rgba(52, 211, 153, 0.12);
        --warn: #FBBF24;
        --danger: #F87171;
        --mono: ui-monospace, 'Cascadia Mono', Consolas, 'SF Mono', Menlo, monospace;
    }

    html, body, [class*="css"], .stApp, button, input, textarea {
        /* System fonts only: no external font requests, so nothing leaves the network. */
        font-family: system-ui, 'Segoe UI', -apple-system, Roboto, 'Helvetica Neue', Arial, sans-serif;
    }

    /* ---------- App shell ---------- */
    .stApp {
        background-color: var(--bg);
        background-image:
            linear-gradient(rgba(34, 211, 238, 0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(34, 211, 238, 0.03) 1px, transparent 1px);
        background-size: 32px 32px;
        color: var(--text);
    }
    .block-container {
        max-width: 1100px;
        padding-top: 1.5rem;
        padding-bottom: 7rem;
    }
    header[data-testid="stHeader"] { background: transparent; }
    #MainMenu, footer, [data-testid="stDeployButton"] { visibility: hidden; }

    h1, h2, h3, h4, p, li, label, span { color: var(--text); }

    /* ---------- Sidebar ---------- */
    [data-testid="stSidebar"] {
        background-color: var(--panel-2);
        border-right: 1px solid var(--border);
    }
    [data-testid="stSidebar"] hr { border-color: var(--border); margin: 1.2rem 0; }

    .side-label {
        font-family: var(--mono);
        font-size: 0.72rem;
        font-weight: 600;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        color: var(--text-muted);
        margin: 0.25rem 0 0.6rem 0;
    }
    .status-card {
        border: 1px solid var(--border);
        background: var(--panel);
        border-radius: 10px;
        padding: 0.85rem 1rem;
        margin-bottom: 0.75rem;
    }
    .status-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 0.88rem;
        padding: 0.3rem 0;
    }
    .status-row .k { color: var(--text-muted); }
    .status-row .v { color: var(--text); font-family: var(--mono); font-size: 0.82rem; }
    .dot {
        display: inline-block; width: 8px; height: 8px; border-radius: 50%;
        margin-right: 6px; vertical-align: middle;
    }
    .dot.ok { background: var(--ok); box-shadow: 0 0 8px var(--ok); }
    .dot.err { background: var(--danger); box-shadow: 0 0 8px var(--danger); }
    .doc-item {
        font-size: 0.86rem;
        color: var(--text);
        padding: 0.4rem 0.2rem;
        border-bottom: 1px solid var(--border);
        word-break: break-all;
    }
    .doc-item:last-child { border-bottom: none; }
    .doc-item code {
        color: var(--accent); background: none; font-family: var(--mono); font-size: 0.75rem;
        margin-right: 6px;
    }

    /* ---------- Inputs / expanders ---------- */
    [data-testid="stExpander"] {
        background-color: var(--panel) !important;
        border: 1px solid var(--border) !important;
        border-radius: 10px !important;
    }
    [data-testid="stExpander"] summary p { color: var(--text) !important; font-weight: 500; }
    [data-testid="stExpander"] summary svg { color: var(--accent) !important; fill: var(--accent) !important; }

    div[data-baseweb="input"], div[data-baseweb="base-input"] {
        background-color: var(--panel) !important;
        border-color: var(--border-strong) !important;
        border-radius: 8px !important;
    }
    div[data-baseweb="input"] input { color: var(--text) !important; }

    .stButton > button {
        background: transparent;
        color: var(--text);
        border: 1px solid var(--border-strong);
        border-radius: 8px;
        font-weight: 500;
        width: 100%;
    }
    .stButton > button:hover { border-color: var(--accent); color: var(--accent); }

    /* ---------- Header ---------- */
    .hero {
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 1rem;
        padding: 1.25rem 1.5rem;
        border: 1px solid var(--border);
        border-radius: 14px;
        background: linear-gradient(135deg, rgba(34,211,238,0.08), rgba(167,139,250,0.06) 60%, transparent), var(--panel);
        margin-bottom: 1rem;
    }
    .hero-left { display: flex; align-items: center; gap: 1rem; }
    .hero-icon {
        width: 52px; height: 52px; border-radius: 12px;
        display: flex; align-items: center; justify-content: center;
        background: var(--accent-soft);
        border: 1px solid rgba(34, 211, 238, 0.35);
        font-size: 1.6rem;
    }
    .hero h1 {
        font-size: 1.6rem; font-weight: 700; margin: 0; padding: 0;
        color: #F8FAFC; letter-spacing: -0.01em;
    }
    .hero .sub { font-size: 0.95rem; color: var(--text-muted); margin-top: 2px; }
    .pills { display: flex; gap: 0.5rem; flex-wrap: wrap; }
    .pill {
        font-family: var(--mono);
        font-size: 0.72rem; font-weight: 500; letter-spacing: 0.06em;
        text-transform: uppercase;
        padding: 0.35rem 0.7rem;
        border-radius: 999px;
        border: 1px solid var(--border-strong);
        color: var(--text);
        background: var(--panel-2);
    }
    .pill.ok { border-color: rgba(52,211,153,0.45); color: var(--ok); background: var(--ok-soft); }
    .pill.err { border-color: rgba(248,113,113,0.45); color: var(--danger); background: rgba(248,113,113,0.1); }

    /* ---------- Metric tiles ---------- */
    .tiles {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 0.75rem;
        margin-bottom: 1rem;
    }
    @media (max-width: 800px) { .tiles { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
    .tile {
        border: 1px solid var(--border);
        background: var(--panel);
        border-radius: 12px;
        padding: 0.9rem 1rem;
    }
    .tile .k {
        font-family: var(--mono);
        font-size: 0.7rem; letter-spacing: 0.12em; text-transform: uppercase;
        color: var(--text-muted);
    }
    .tile .v {
        font-size: 1.15rem; font-weight: 600; color: #F8FAFC; margin-top: 0.3rem;
        white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }

    /* ---------- Disclosure banner ---------- */
    .notice {
        display: flex; gap: 0.75rem; align-items: flex-start;
        border: 1px solid rgba(34, 211, 238, 0.3);
        border-left: 4px solid var(--accent);
        background: var(--accent-soft);
        border-radius: 10px;
        padding: 0.8rem 1rem;
        font-size: 0.93rem;
        line-height: 1.55;
        color: var(--text);
        margin-bottom: 1.5rem;
    }
    .notice b { color: var(--accent); }

    /* ---------- Empty state ---------- */
    .empty {
        text-align: center;
        padding: 3rem 1rem;
        border: 1px dashed var(--border-strong);
        border-radius: 14px;
        color: var(--text-muted);
    }
    .empty h3 { color: var(--text); font-weight: 600; font-size: 1.15rem; margin-bottom: 0.4rem; }
    .empty p { color: var(--text-muted); font-size: 0.95rem; margin: 0; }

    /* ---------- Chat messages ---------- */
    [data-testid="stChatMessage"] {
        background-color: var(--panel);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 1rem 1.25rem;
        margin-bottom: 1rem;
    }
    [data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"]),
    [data-testid="stChatMessage"]:has(div[aria-label="Chat message from user"]) {
        background-color: var(--panel-2);
        border-left: 3px solid var(--accent);
    }
    [data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarAssistant"]),
    [data-testid="stChatMessage"]:has(div[aria-label="Chat message from assistant"]) {
        border-left: 3px solid var(--ai);
    }
    [data-testid="stChatMessageAvatarUser"] { background-color: var(--accent) !important; }
    [data-testid="stChatMessageAvatarAssistant"] { background-color: var(--ai) !important; }

    [data-testid="stChatMessage"] p,
    [data-testid="stChatMessage"] li {
        color: var(--text) !important;
        font-size: 1rem;
        line-height: 1.7;
    }
    [data-testid="stChatMessage"] strong { color: #F8FAFC; }
    [data-testid="stChatMessage"] code {
        color: var(--accent); background: var(--panel-2); font-family: var(--mono);
    }

    .msg-role {
        font-family: var(--mono);
        font-size: 0.7rem; font-weight: 600; letter-spacing: 0.14em; text-transform: uppercase;
        margin-bottom: 0.35rem;
    }
    .msg-role.user { color: var(--accent); }
    .msg-role.ai { color: var(--ai); }

    /* Source citations */
    .src {
        border: 1px solid var(--border);
        background: var(--panel-2);
        border-radius: 8px;
        padding: 0.7rem 0.9rem;
        margin-bottom: 0.6rem;
    }
    .src-head { display: flex; justify-content: space-between; gap: 0.75rem; flex-wrap: wrap; }
    .src-file { font-weight: 600; color: var(--text); font-size: 0.92rem; }
    .src-loc {
        font-family: var(--mono); font-size: 0.75rem; color: var(--accent);
        background: var(--accent-soft); border-radius: 4px; padding: 0.1rem 0.45rem;
    }
    .src-idx { font-family: var(--mono); color: var(--text-muted); margin-right: 0.4rem; }
    .src-excerpt {
        margin-top: 0.45rem;
        font-size: 0.88rem; line-height: 1.55;
        color: var(--text-muted);
        border-left: 2px solid var(--border-strong);
        padding-left: 0.7rem;
    }

    /* Alerts */
    .stAlert { border-radius: 8px; }
    .stAlert p { color: var(--text) !important; }

    /* ---------- Chat input ---------- */
    [data-testid="stBottom"], [data-testid="stBottom"] > div {
        background-color: var(--bg) !important;
    }
    [data-testid="stBottom"] { border-top: 1px solid var(--border); }
    [data-testid="stChatInput"] {
        background-color: var(--panel) !important;
        border: 1px solid var(--border-strong) !important;
        border-radius: 12px !important;
    }
    [data-testid="stChatInput"]:focus-within {
        border-color: var(--accent) !important;
        box-shadow: 0 0 0 3px rgba(34, 211, 238, 0.15) !important;
    }
    [data-testid="stChatInput"] div[data-baseweb="base-input"],
    [data-testid="stChatInput"] div[data-baseweb="textarea"],
    [data-testid="stChatInput"] textarea {
        background-color: var(--panel) !important;
        border: none !important;
        color: #F8FAFC !important;
        caret-color: var(--accent) !important;
        font-size: 1rem !important;
    }
    [data-testid="stChatInput"] textarea::placeholder { color: var(--text-muted) !important; }
    [data-testid="stChatInput"] button {
        background-color: var(--accent) !important;
        border-radius: 8px !important;
    }
    [data-testid="stChatInput"] button svg { fill: var(--bg) !important; color: var(--bg) !important; }
    [data-testid="stChatInput"] button:disabled { background-color: var(--border-strong) !important; }

    /* Spinner */
    [data-testid="stSpinner"] p { color: var(--text-muted) !important; font-family: var(--mono); font-size: 0.85rem; }
    </style>
""", unsafe_allow_html=True)


@st.cache_resource
def get_rag():
    # Indexing happens after the document list is loaded, so an empty
    # SQLite store does not take the whole app offline.
    init_db()
    return PolicyRAG()

try:
    rag = get_rag()
    startup_error = None
except Exception as exc:
    rag = None
    # Full details go to the server console only; users get a safe hint.
    print(f"Startup failed: {exc!r}")
    if isinstance(exc, ValueError):
        startup_error = str(exc)
    else:
        startup_error = (
            f"{type(exc).__name__}: check that Ollama is running and the models are pulled. "
            "See the server console for details."
        )

def check_admin_password():
    """Verify the admin password once per submission and audit failures."""
    attempt = st.session_state.get("admin_pw", "")
    st.session_state.admin_pw = ""  # never keep the password in widget state
    if not attempt:
        return
    if hmac.compare_digest(attempt.encode(), ADMIN_PASSWORD.encode()):
        st.session_state.admin_ok = True
        st.session_state.admin_failures = 0
        write_audit_log("admin_login", "audit_panel", "success")
    else:
        st.session_state.admin_failures += 1
        # Log a constant, never the attempted password (or its hash).
        write_audit_log(
            "admin_login_failed", "audit_panel",
            f"attempt={st.session_state.admin_failures}",
        )

SUPPORTED_UPLOAD_TYPES = {".pdf", ".docx", ".txt", ".md"}


def validate_upload(filename, content):
    """Mirror ingest_policies.validate_file for in-memory uploads. Returns (ok, reason)."""
    extension = Path(filename).suffix.lower()
    if extension not in SUPPORTED_UPLOAD_TYPES:
        return False, "Unsupported file type"
    if not content:
        return False, "File is empty"
    if len(content) > MAX_UPLOAD_BYTES:
        return False, f"File exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit"
    if extension == ".pdf" and not content.startswith(b"%PDF-"):
        return False, "Invalid PDF signature"
    if extension == ".docx" and not is_zipfile(BytesIO(content)):
        return False, "Invalid DOCX archive"
    if extension in {".txt", ".md"}:
        try:
            content.decode("utf-8")
        except UnicodeDecodeError:
            return False, "Text file must use UTF-8 encoding"
    # Only store files we can actually read (rejects encrypted/scanned PDFs).
    try:
        if not extract_records(filename, extension, content):
            return False, "No extractable text (scanned PDF? needs OCR)"
    except Exception:
        return False, "File could not be parsed"
    return True, None


def handle_document_uploads(uploaded_files):
    """Validate and store uploads. Returns (imported_count, messages)."""
    imported, messages = 0, []
    for uploaded in uploaded_files:
        filename = Path(uploaded.name).name
        content = uploaded.getvalue()
        ok, reason = validate_upload(filename, content)
        if not ok:
            write_audit_log("upload_rejected", filename, reason)
            messages.append(f"Skipped {filename}: {reason}")
            continue
        if import_document(filename, content, extension=Path(filename).suffix.lower()):
            write_audit_log("upload_imported", filename)
            messages.append(f"Imported {filename}")
            imported += 1
        else:
            write_audit_log("upload_duplicate", filename)
            messages.append(f"Skipped {filename}: duplicate content")
    return imported, messages


documents = []
documents_error = None
index_error = None
if not startup_error:
    try:
        documents = list_documents()
    except Exception as exc:
        documents_error = str(exc)

    if documents:
        try:
            rag.rebuild_index()
        except Exception as exc:
            print(f"Indexing failed: {exc!r}")
            index_error = str(exc) if isinstance(exc, ValueError) else (
                f"{type(exc).__name__}: indexing failed. See the server console for details."
            )

online = startup_error is None
model_name = html.escape(str(OLLAMA_MODEL))

# Header
status_pill = (
    "<span class='pill ok'><span class='dot ok'></span>Online</span>"
    if online else
    "<span class='pill err'><span class='dot err'></span>Offline</span>"
)
st.markdown(f"""
    <div class='hero'>
        <div class='hero-left'>
            <div class='hero-icon'>🛡️</div>
            <div>
                <h1>Secure Policy Assistant</h1>
                <div class='sub'>Retrieval-augmented answers from your approved policy library</div>
            </div>
        </div>
        <div class='pills'>
            {status_pill}
            {"<span class='pill'>Local inference</span><span class='pill'>Zero data egress</span>"
             if OLLAMA_IS_LOCAL else "<span class='pill err'>Remote model host</span>"}
            <span class='pill'>Audit logged</span>
        </div>
    </div>
    <div class='tiles'>
        <div class='tile'><div class='k'>System</div><div class='v'>{"Operational" if online else "Unavailable"}</div></div>
        <div class='tile'><div class='k'>Policies indexed</div><div class='v'>{len(documents)}</div></div>
        <div class='tile'><div class='k'>Language model</div><div class='v' title='{model_name}'>{model_name}</div></div>
        <div class='tile'><div class='k'>Retrieval depth</div><div class='v'>Top {TOP_K} chunks</div></div>
    </div>
    <div class='notice'>
        <span>🤖</span>
        <div><b>AI disclosure.</b> You are interacting with a local AI assistant. Answers are generated
        from approved company documents. Always verify critical information against the original policy.</div>
    </div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("<div class='side-label'>System status</div>", unsafe_allow_html=True)

    if startup_error:
        st.markdown("""
            <div class='status-card'>
                <div class='status-row'><span class='k'>Engine</span><span class='v'><span class='dot err'></span>OFFLINE</span></div>
            </div>
        """, unsafe_allow_html=True)
        st.error("The policy assistant could not start.")
        st.caption(startup_error)
    else:
        st.markdown(f"""
            <div class='status-card'>
                <div class='status-row'><span class='k'>Engine</span><span class='v'><span class='dot ok'></span>ONLINE</span></div>
                <div class='status-row'><span class='k'>Model</span><span class='v'>{model_name}</span></div>
                <div class='status-row'><span class='k'>Documents</span><span class='v'>{len(documents)}</span></div>
                <div class='status-row'><span class='k'>Top-K</span><span class='v'>{TOP_K}</span></div>
            </div>
        """, unsafe_allow_html=True)

        st.markdown("<div class='side-label'>Knowledge base</div>", unsafe_allow_html=True)
        if index_error:
            st.error("Policy index could not be built.")
            st.caption(index_error)
        if documents_error:
            st.error("Could not load document list.")
        else:
            with st.expander(f"📂 Stored documents ({len(documents)})"):
                if documents:
                    items = "".join(
                        f"<div class='doc-item'><code>{i:02d}</code>{html.escape(str(doc['filename']))}</div>"
                        for i, doc in enumerate(documents, start=1)
                    )
                    st.markdown(items, unsafe_allow_html=True)
                else:
                    st.info("No documents imported.")

        uploaded_files = st.file_uploader(
            "Add policy documents",
            type=["pdf", "docx", "txt", "md"],
            accept_multiple_files=True,
        )
        if uploaded_files and st.button("Import & index uploaded files"):
            with st.spinner("Importing and indexing documents..."):
                imported, upload_messages = handle_document_uploads(uploaded_files)
                if imported:
                    try:
                        upload_messages.append(rag.rebuild_index(force=True))
                    except Exception as exc:
                        print(f"Indexing failed: {exc!r}")
                        upload_messages.append(f"Indexing failed: {type(exc).__name__}")
            st.session_state.upload_messages = upload_messages
            st.rerun()
        # st.text, not markdown: filenames are user-controlled.
        for msg in st.session_state.pop("upload_messages", []):
            st.text(msg)

    st.divider()

    st.markdown("<div class='side-label'>Security audit</div>", unsafe_allow_html=True)

    st.session_state.setdefault("admin_ok", False)
    st.session_state.setdefault("admin_failures", 0)
    locked_out = st.session_state.admin_failures >= ADMIN_MAX_ATTEMPTS

    if not ADMIN_PASSWORD:
        st.caption("Audit panel locked: set ADMIN_PASSWORD in .env to enable it.")
    elif st.session_state.admin_ok:
        st.success("Authenticated")
        log_lines = read_audit_tail(25)
        if log_lines:
            st.code("\n".join(log_lines), language="json")
            st.caption("Showing latest security events.")
        else:
            st.info("No security events logged yet.")
        if st.button("Lock audit panel"):
            st.session_state.admin_ok = False
            st.rerun()
    elif locked_out:
        st.error("Too many failed attempts. Restart your browser session to try again.")
    else:
        st.text_input(
            "Admin password",
            type="password",
            placeholder="Enter admin password",
            key="admin_pw",
            on_change=check_admin_password,
        )
        if st.session_state.admin_failures:
            remaining = ADMIN_MAX_ATTEMPTS - st.session_state.admin_failures
            st.error(f"Access denied. {remaining} attempt(s) remaining.")

    st.divider()

    st.markdown("<div class='side-label'>Session</div>", unsafe_allow_html=True)
    if st.button("Clear conversation"):
        st.session_state.messages = []
        st.rerun()
    st.caption("Admin-managed local document storage.")

if "messages" not in st.session_state:
    st.session_state.messages = []

def show_sources(sources, expanded=False):
    if not sources:
        return
    with st.expander(f"📄 Sources used ({len(sources)})", expanded=expanded):
        cards = []
        for i, source in enumerate(sources, start=1):
            filename = html.escape(str(source.get("file", "Unknown document")))
            location = html.escape(str(source.get("location", "Location unavailable")))
            excerpt = source.get("excerpt", "")
            excerpt_html = f"<div class='src-excerpt'>“{html.escape(str(excerpt))}”</div>" if excerpt else ""
            cards.append(
                f"<div class='src'><div class='src-head'>"
                f"<span class='src-file'><span class='src-idx'>[{i}]</span>{filename}</span>"
                f"<span class='src-loc'>{location}</span></div>{excerpt_html}</div>"
            )
        st.markdown("".join(cards), unsafe_allow_html=True)

def show_user_text(text):
    """Render user input as plain text: no markdown images/links or HTML."""
    st.markdown(
        f"<p style='white-space: pre-wrap; margin: 0;'>{html.escape(text)}</p>",
        unsafe_allow_html=True,
    )

def role_label(role):
    if role == "user":
        st.markdown("<div class='msg-role user'>You</div>", unsafe_allow_html=True)
    else:
        st.markdown("<div class='msg-role ai'>Policy Assistant</div>", unsafe_allow_html=True)

if not st.session_state.messages:
    st.markdown("""
        <div class='empty'>
            <h3>Ask about your organization's policies</h3>
            <p>Answers cite the exact documents and sections they were drawn from.</p>
        </div>
    """, unsafe_allow_html=True)

for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        role_label(message["role"])
        if message["role"] == "user":
            show_user_text(message["content"])
        else:
            st.markdown(message["content"])
        if message.get("warnings"):
            for warning in message["warnings"]:
                st.warning(warning)
        show_sources(message.get("sources", []))

st.session_state.setdefault("blocked_count", 0)
st.session_state.setdefault("blocked_until", 0.0)
cooldown_left = int(st.session_state.blocked_until - time.time())
if cooldown_left > 0:
    st.warning(
        f"Chat paused for {cooldown_left} s after repeated blocked requests. "
        "This activity has been logged."
    )

has_index = rag is not None and rag.collection.count() > 0
question = st.chat_input(
    "Ask a question about policies or contracts..." if has_index
    else "Waiting for policy documents to be imported...",
    disabled=not has_index or cooldown_left > 0,
)

if question:
    st.session_state.messages.append({"role": "user", "content": question})
    with st.chat_message("user"):
        role_label("user")
        show_user_text(question)

    with st.chat_message("assistant"):
        role_label("assistant")
        with st.spinner("Retrieving context and applying security guardrails..."):
            try:
                answer, sources, warnings = rag.ask(question)
            except Exception as e:
                # Keep internals (paths, hosts, stack details) out of the UI.
                print(f"ask() failed: {e!r}")
                write_audit_log("error", question, type(e).__name__)
                answer = "Sorry, an internal error occurred."
                sources = []
                warnings = ["The assistant could not complete this request. Please try again shortly."]

        st.markdown(answer)
        if warnings:
            for warning in warnings:
                st.warning(warning)
        show_sources(sources, expanded=True)

    st.session_state.messages.append({
        "role": "assistant",
        "content": answer,
        "sources": sources,
        "warnings": warnings
    })

    # Throttle sessions that keep probing the guardrails.
    if answer in BLOCKED_ANSWERS:
        st.session_state.blocked_count += 1
        if st.session_state.blocked_count >= MAX_BLOCKED_PER_SESSION:
            st.session_state.blocked_count = 0
            st.session_state.blocked_until = time.time() + BLOCK_COOLDOWN_SECONDS
            write_audit_log("session_throttled", question, f"cooldown={BLOCK_COOLDOWN_SECONDS}s")
            st.rerun()
