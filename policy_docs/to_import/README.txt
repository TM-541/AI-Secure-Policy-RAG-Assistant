Place administrator-managed policy files here (.pdf, .docx, .txt, .md).
This README is ignored by the importer.

From the project root run: python ingest_policies.py
Original files are stored in data/policy_store.sqlite3; searchable chunks/embeddings in data/chroma_db.
List stored documents:  python ingest_policies.py --list
Remove a document:      python ingest_policies.py --remove <ID>

These files are confidential and excluded from git by .gitignore.
Employees then run: streamlit run app.py
