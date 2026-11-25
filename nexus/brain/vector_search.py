"""TF-IDF vector search for fuzzy vulnerability matching — no LLM needed."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import numpy as np
from scipy.sparse import csr_matrix

_TOKEN_RE = re.compile(r"\d+(?:\.\d+)+|[a-z0-9]+(?:-[a-z0-9]+)*")


@dataclass
class SearchEntry:
    id: str
    text: str
    metadata: dict = field(default_factory=dict)


class VectorSearch:
    """Lightweight TF-IDF based fuzzy search engine.

    Matches vulnerability descriptions, CVEs, and service banners
    without requiring exact version strings. Uses sparse matrices
    for memory efficiency (~80MB for 10K entries).
    """

    def __init__(self) -> None:
        self._entries: list[SearchEntry] = []
        self._id_index: dict[str, int] = {}
        self._vocab: dict[str, int] = {}
        self._idf: np.ndarray | None = None
        self._tfidf_matrix: csr_matrix | None = None
        self._built = False

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def add_entry(self, id: str, text: str, metadata: dict | None = None) -> None:
        entry = SearchEntry(id=id, text=text.lower(), metadata=metadata or {})
        if id in self._id_index:
            self._entries[self._id_index[id]] = entry
        else:
            self._id_index[id] = len(self._entries)
            self._entries.append(entry)
        self._built = False

    def add_entries(self, entries: list[tuple[str, str, dict]]) -> None:
        for id_, text, meta in entries:
            self.add_entry(id_, text, meta)

    def _tokenize(self, text: str) -> list[str]:
        """Tokenizer preserving dotted version numbers and splitting hyphenated IDs (e.g. CVEs)."""
        tokens: list[str] = []
        for tok in _TOKEN_RE.findall(text.lower()):
            if "-" in tok:
                if len(tok) >= 2:
                    tokens.append(tok)
                for part in tok.split("-"):
                    if len(part) >= 2:
                        tokens.append(part)
            elif len(tok) >= 2:
                tokens.append(tok)
        return tokens

    def build_index(self) -> None:
        """Build the TF-IDF matrix from all entries."""
        if not self._entries:
            self._built = True
            return

        # Build vocabulary
        self._vocab = {}
        doc_tokens: list[list[str]] = []
        for entry in self._entries:
            tokens = self._tokenize(entry.text)
            doc_tokens.append(tokens)
            for tok in set(tokens):
                if tok not in self._vocab:
                    self._vocab[tok] = len(self._vocab)

        n_docs = len(self._entries)
        n_vocab = len(self._vocab)

        if n_vocab == 0:
            self._built = True
            return

        # Compute document frequency
        df = np.zeros(n_vocab)
        for tokens in doc_tokens:
            seen = set()
            for tok in tokens:
                idx = self._vocab.get(tok)
                if idx is not None and idx not in seen:
                    df[idx] += 1
                    seen.add(idx)

        # Smooth IDF = log((N + 1) / (df + 1)) + 1 (stays >= 1.0 even when N == 1)
        self._idf = np.log((n_docs + 1) / (df + 1)) + 1

        # Build sparse TF-IDF matrix
        rows, cols, data = [], [], []
        for doc_idx, tokens in enumerate(doc_tokens):
            tf: dict[int, int] = {}
            for tok in tokens:
                idx = self._vocab.get(tok)
                if idx is not None:
                    tf[idx] = tf.get(idx, 0) + 1
            # Normalize TF
            max_tf = max(tf.values()) if tf else 1
            for idx, count in tf.items():
                tfidf = (count / max_tf) * self._idf[idx]
                rows.append(doc_idx)
                cols.append(idx)
                data.append(tfidf)

        self._tfidf_matrix = csr_matrix((data, (rows, cols)), shape=(n_docs, n_vocab))
        # L2 normalize rows
        norms = np.sqrt(self._tfidf_matrix.multiply(self._tfidf_matrix).sum(axis=1))
        norms = np.asarray(norms).flatten()
        norms[norms == 0] = 1.0
        self._tfidf_matrix = self._tfidf_matrix.multiply(1.0 / norms[:, np.newaxis])
        self._tfidf_matrix = csr_matrix(self._tfidf_matrix)

        self._built = True

    def search(self, query: str, top_k: int = 10) -> list[tuple[str, float, dict]]:
        """Search for entries matching the query.

        Returns list of (id, score, metadata) sorted by relevance.
        """
        if not self._built:
            self.build_index()
        if self._tfidf_matrix is None or self._idf is None:
            return []

        tokens = self._tokenize(query)
        if not tokens:
            return []

        # Build query vector
        n_vocab = len(self._vocab)
        q_vec = np.zeros(n_vocab)
        for tok in tokens:
            idx = self._vocab.get(tok)
            if idx is not None:
                q_vec[idx] += 1
        # Apply IDF
        q_vec = q_vec * self._idf
        # L2 normalize
        norm = np.linalg.norm(q_vec)
        if norm > 0:
            q_vec /= norm

        # Cosine similarity
        scores = self._tfidf_matrix.dot(q_vec)
        if hasattr(scores, "toarray"):
            scores = np.asarray(scores).flatten()

        # Top-k
        top_indices = np.argsort(scores)[::-1][:top_k]
        results = []
        for idx in top_indices:
            score = float(scores[idx])
            if score > 0.01:
                entry = self._entries[idx]
                results.append((entry.id, score, entry.metadata))
        return results
