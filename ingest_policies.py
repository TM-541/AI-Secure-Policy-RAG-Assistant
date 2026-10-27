import argparse
import hashlib
from pathlib import Path
from zipfile import is_zipfile

from config import IMPORT_DIR, MAX_UPLOAD_BYTES
from storage import init_db, import_document, list_documents, delete_document
from rag_engine import PolicyRAG, extract_records


SUPPORTED_EXTENSIONS = {".pdf", ".docx", ".txt", ".md"}
MAX_FILE_SIZE = MAX_UPLOAD_BYTES


def validate_file(path, root):
    """Perform basic file type and size checks before importing."""
    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        return False, "Unsupported file type"

    if path.is_symlink() or not path.is_file():
        return False, "Not a regular file"

    # Reject anything that resolves outside the import folder (symlinked dirs, junctions).
    if not path.resolve().is_relative_to(root):
        return False, "File resolves outside the import folder"

    if path.stat().st_size == 0:
        return False, "File is empty"

    if path.stat().st_size > MAX_FILE_SIZE:
        return False, f"File exceeds the {MAX_FILE_SIZE // (1024 * 1024)} MB limit"

    extension = path.suffix.lower()

    if extension == ".pdf":
        with path.open("rb") as file:
            if not file.read(5).startswith(b"%PDF-"):
                return False, "Invalid PDF signature"

    elif extension == ".docx":
        if not is_zipfile(path):
            return False, "Invalid DOCX archive"

    elif extension in {".txt", ".md"}:
        try:
            path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return False, "Text file must use UTF-8 encoding"

    return True, None


def main():
    parser = argparse.ArgumentParser(
        description="Import company policy documents into the RAG system."
    )
    parser.add_argument(
        "--folder",
        default=str(IMPORT_DIR),
        help="Folder containing policy documents."
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List stored documents and exit."
    )
    parser.add_argument(
        "--remove",
        type=int,
        nargs="+",
        metavar="ID",
        help="Remove stored document(s) by ID (see --list), then re-index."
    )
    args = parser.parse_args()

    init_db()

    if args.list:
        for doc in sorted(list_documents(), key=lambda d: d["id"]):
            print(f"{doc['id']:>4}  {doc['filename']}  (imported {doc['imported_at'][:10]})")
        return

    if args.remove:
        removed = 0
        for doc_id in args.remove:
            filename = delete_document(doc_id)
            if filename:
                print(f"Removed {doc_id}: {filename}")
                removed += 1
            else:
                print(f"No document with ID {doc_id}")
        if removed:
            print("\nIndexing result:")
            print(PolicyRAG().rebuild_index(force=True))
        return

    folder = Path(args.folder).resolve()
    folder.mkdir(parents=True, exist_ok=True)

    files = sorted(
        path for path in folder.rglob("*")
        if path.is_file() and not path.is_symlink()
    )

    if not files:
        print(f"No files found in: {folder}")
        return

    added = 0

    for path in files:
        if path.name.lower() == "readme.txt":
            continue

        valid, reason = validate_file(path, folder)

        if not valid:
            print(f"Skipped {path.name}: {reason}")
            continue

        try:
            content = path.read_bytes()
            digest = hashlib.sha256(content).hexdigest()

            # Only store files we can actually read (rejects encrypted/scanned PDFs).
            try:
                if not extract_records(path.name, path.suffix, content):
                    print(f"Skipped {path.name}: no extractable text (scanned PDF? needs OCR)")
                    continue
            except Exception as exc:
                print(f"Skipped {path.name}: could not be parsed ({exc})")
                continue

            inserted = import_document(
                filename=path.name,
                content=content,
                extension=path.suffix.lower(),
                sha256=digest,
            )

            if inserted:
                print(f"Imported: {path.name}")
                added += 1
            else:
                print(f"Skipped duplicate content: {path.name}")

        except OSError as exc:
            print(f"Could not read {path.name}: {exc}")

    print(f"\nNew documents imported: {added}")

    if added:
        rag = PolicyRAG()
        result = rag.rebuild_index(force=True)
        print("\nIndexing result:")
        print(result)
    else:
        print("No new documents. Existing vector index was not rebuilt.")


if __name__ == "__main__":
    main()
