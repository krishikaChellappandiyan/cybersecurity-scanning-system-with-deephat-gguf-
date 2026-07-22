from embedding.embedder import Embedder
from storage.vector_db import VectorDB
from retrieval.ranker import Reranker
from retrieval.query_rewriter import QueryRewriter
from retrieval.bm25_retriever import BM25Retriever


class Retriever:
    def __init__(self):
        self.embedder = Embedder()
        self.bm25_retriever = BM25Retriever()
        self.reranker = Reranker()
        self.vector_db = VectorDB()
        self.query_rewriter = QueryRewriter()

    def normalize_result(self, result, retrieval_type):
        if retrieval_type == "faiss":
            payload = result["payload"]

            return {
                "chunk_id": payload.get("chunk_id"),
                "content": payload.get("content", ""),
                "url": payload.get("url") or payload.get("source"),
                "metadata": payload,
                "score": float(result["score"]),
                "retrieval_type": "faiss"
            }

        if retrieval_type == "bm25":
            metadata = result.get("metadata", {})

            return {
                "chunk_id": result.get("chunk_id") or metadata.get("chunk_id"),
                "content": result.get("content", ""),
                "url": metadata.get("url") or metadata.get("source"),
                "metadata": metadata,
                "score": float(result["score"]),
                "retrieval_type": "bm25"
            }

    def retrieve(self, query, top_k=5):
        rewritten_query = self.query_rewriter.rewrite(query)

        bm25_results = self.bm25_retriever.search(
            rewritten_query,
            top_k=20
        )

        query_vector = self.embedder.encode(rewritten_query)

        print("Query vector shape:", query_vector.shape)
        print("Vectors in index:", self.vector_db.index.ntotal)
        print("BM25 results:", len(bm25_results))

        faiss_results = self.vector_db.search(
            query_vector,
            top_k=20
        )

        retrieved_docs = []

        for result in faiss_results:
            retrieved_docs.append(
                self.normalize_result(result, "faiss")
            )

        for result in bm25_results:
            retrieved_docs.append(
                self.normalize_result(result, "bm25")
            )

        if not retrieved_docs:
            return []

        retrieved_docs = self.deduplicate(retrieved_docs)

        retrieved_docs = self.reranker.rank(
            rewritten_query,
            retrieved_docs
        )

        if not retrieved_docs:
            return []

        final_docs = self.limit_per_url(
            retrieved_docs,
            top_k=top_k,
            max_per_url=2
        )

        for i, doc in enumerate(final_docs, start=1):
            print(f"\nDoc {i}")
            print("URL:", doc.get("url"))
            print("Retrieval Type:", doc.get("retrieval_type"))
            print("Search Score:", doc["score"])
            print("Rerank Score:", doc["rerank_score"])
            print(doc["content"][:300])

        return final_docs

    def deduplicate(self, docs):
        seen_chunk_ids = set()
        seen_content = set()
        unique_docs = []

        for doc in docs:
            chunk_id = doc.get("chunk_id")
            content = doc.get("content", "").strip()

            content_key = " ".join(content.lower().split()[:80])

            if chunk_id and chunk_id in seen_chunk_ids:
                continue

            if content_key in seen_content:
                continue

            if chunk_id:
                seen_chunk_ids.add(chunk_id)

            seen_content.add(content_key)
            unique_docs.append(doc)

        return unique_docs

    def limit_per_url(self, docs, top_k=5, max_per_url=2):
        final_docs = []
        url_count = {}

        for doc in docs:
            url = doc.get("url", "unknown")

            if url_count.get(url, 0) >= max_per_url:
                continue

            final_docs.append(doc)
            url_count[url] = url_count.get(url, 0) + 1

            if len(final_docs) >= top_k:
                break

        return final_docs