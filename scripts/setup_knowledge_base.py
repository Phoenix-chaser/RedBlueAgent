#!/usr/bin/env python3
"""
setup_knowledge_base.py - Ingest CVE data and security knowledge into vector store.

Usage:
    python scripts/setup_knowledge_base.py --cve-dir data/knowledge_base/cve_entries
    python scripts/setup_knowledge_base.py --text-dir data/knowledge_base/exploit_techniques
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import click
from pathlib import Path
from rich.console import Console

console = Console()


@click.command()
@click.option("--cve-dir", default="data/knowledge_base/cve_entries", show_default=True)
@click.option("--text-dir", default="data/knowledge_base/exploit_techniques", show_default=True)
@click.option(
    "--vector-store-dir",
    default="data/knowledge_base/vector_store",
    show_default=True,
)
@click.option(
    "--embedding-model",
    default="all-MiniLM-L6-v2",
    show_default=True,
)
def main(cve_dir: str, text_dir: str, vector_store_dir: str, embedding_model: str):
    """Ingest security knowledge into the RAG vector store."""
    from modules.context_management.rag.knowledge_base import RAGKnowledgeBase

    kb = RAGKnowledgeBase(persist_dir=vector_store_dir, embedding_model=embedding_model)

    if not kb.is_available():
        console.print(
            "[red]chromadb or sentence-transformers not installed.[/red]\n"
            "Run: pip install chromadb sentence-transformers"
        )
        sys.exit(1)

    total = 0

    # Ingest CVE JSON files
    cve_path = Path(cve_dir)
    if cve_path.exists():
        json_files = list(cve_path.glob("*.json"))
        console.print(f"Found {len(json_files)} CVE JSON files in {cve_dir}")
        for f in json_files:
            count = kb.ingest_cve_json(str(f))
            console.print(f"  Ingested {count} CVEs from {f.name}")
            total += count

    # Ingest plain text knowledge files
    text_path = Path(text_dir)
    if text_path.exists():
        txt_files = list(text_path.glob("*.txt")) + list(text_path.glob("*.md"))
        console.print(f"Found {len(txt_files)} text knowledge files in {text_dir}")
        for f in txt_files:
            count = kb.ingest_text_file(str(f), doc_id_prefix=f.stem)
            console.print(f"  Ingested {count} chunks from {f.name}")
            total += count

    console.print(f"\n[green]Total documents ingested: {total}[/green]")
    console.print(f"Vector store: {vector_store_dir}")


if __name__ == "__main__":
    main()
