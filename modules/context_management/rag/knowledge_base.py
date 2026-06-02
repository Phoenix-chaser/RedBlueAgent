"""
RAGKnowledgeBase - contextual CVE and exploitation technique retrieval.
Backed by ChromaDB with sentence-transformer embeddings.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class RAGDocument:
    def __init__(self, page_content: str, metadata: dict):
        self.page_content = page_content
        self.metadata = metadata


class RAGKnowledgeBase:
    """
    Provides CVE + exploitation technique retrieval via semantic search.
    Falls back gracefully if chromadb/sentence-transformers not installed.
    """

    def __init__(
        self,
        persist_dir: str = "data/knowledge_base/vector_store",
        embedding_model: str = "all-MiniLM-L6-v2",
    ):
        self.persist_dir = Path(persist_dir)
        self.embedding_model = embedding_model
        self._collection = None
        self._available = False
        self._try_init()

    def _try_init(self) -> None:
        try:
            import chromadb
            from chromadb.utils import embedding_functions

            client = chromadb.PersistentClient(path=str(self.persist_dir))
            ef = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name=self.embedding_model
            )
            self._collection = client.get_or_create_collection(
                name="security_knowledge",
                embedding_function=ef,
            )
            self._available = True
        except Exception:
            self._available = False

    def is_available(self) -> bool:
        return self._available

    def query_for_service(
        self, service: str, version: str = "", top_k: int = 5
    ) -> list[RAGDocument]:
        query = f"{service} {version} vulnerability exploit CVE".strip()
        return self._query(query, top_k)

    def query_for_exploitation(
        self, vuln_title: str, top_k: int = 3
    ) -> list[RAGDocument]:
        query = f"exploit technique {vuln_title} metasploit proof of concept"
        return self._query(query, top_k)

    def _query(self, query: str, top_k: int) -> list[RAGDocument]:
        if not self._available or self._collection is None:
            return []
        try:
            results = self._collection.query(
                query_texts=[query],
                n_results=min(top_k, self._collection.count() or 1),
            )
            docs = []
            documents = results.get("documents", [[]])[0]
            metadatas = results.get("metadatas", [[]])[0]
            for content, meta in zip(documents, metadatas):
                docs.append(RAGDocument(page_content=content, metadata=meta or {}))
            return docs
        except Exception:
            return []

    def ingest_cve_json(self, cve_json_path: str) -> int:
        """Ingest NVD CVE JSON feed into the vector store."""
        if not self._available:
            return 0

        with open(cve_json_path) as f:
            data = json.load(f)

        items = data.get("CVE_Items", data.get("vulnerabilities", []))
        documents, metadatas, ids = [], [], []

        for i, item in enumerate(items):
            cve_id, description, cvss = self._extract_cve_fields(item)
            if not description:
                continue
            documents.append(f"{cve_id}: {description}")
            metadatas.append({"cve_id": cve_id, "cvss": cvss})
            ids.append(cve_id or f"cve_{i}")

        if documents:
            # Batch insert in chunks of 100
            for start in range(0, len(documents), 100):
                self._collection.upsert(
                    documents=documents[start:start + 100],
                    metadatas=metadatas[start:start + 100],
                    ids=ids[start:start + 100],
                )

        return len(documents)

    def ingest_text_file(self, text_path: str, doc_id_prefix: str = "doc") -> int:
        """Ingest a plain text knowledge file (one paragraph per chunk)."""
        if not self._available:
            return 0

        text = Path(text_path).read_text(encoding="utf-8")
        chunks = [p.strip() for p in text.split("\n\n") if len(p.strip()) > 50]

        documents = chunks
        metadatas = [{"source": text_path}] * len(chunks)
        ids = [f"{doc_id_prefix}_{i}" for i in range(len(chunks))]

        if documents:
            self._collection.upsert(documents=documents, metadatas=metadatas, ids=ids)

        return len(documents)

    def _extract_cve_fields(self, item: dict) -> tuple[str, str, str]:
        # NVD format v1.0 and v2.0 support
        try:
            cve_obj = item.get("cve", item)
            cve_id = cve_obj.get("CVE_data_meta", {}).get("ID", "") or cve_obj.get("id", "")

            # Description
            desc_data = (
                cve_obj.get("description", {}).get("description_data", [])
                or cve_obj.get("descriptions", [])
            )
            description = ""
            for d in desc_data:
                if d.get("lang") in ("en", "eng"):
                    description = d.get("value", "")
                    break

            # CVSS
            impact = item.get("impact", {})
            cvss = (
                str(impact.get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore", ""))
                or str(impact.get("baseMetricV2", {}).get("cvssV2", {}).get("baseScore", ""))
            )
            return cve_id, description, cvss
        except Exception:
            return "", "", ""
