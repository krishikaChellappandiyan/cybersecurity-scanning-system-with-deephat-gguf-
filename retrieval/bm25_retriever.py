from rank_bm25 import BM25Okapi
from storage.metadata_db import MetadataDB


class BM25Retriever:
    def __init__(self):
        self.metadata_db = MetadataDB()
        self.documents = self.metadata_db.fetch_all()

        self.tokenized_docs = [
            doc["content"].lower().split()
            for doc in self.documents
        ]

        self.bm25 = BM25Okapi(self.tokenized_docs)

    def search(self, query, top_k=10):
        query_tokens = query.lower().split()
        scores = self.bm25.get_scores(query_tokens)

        results = []

        ranked_results = sorted(
            enumerate(scores),
            key=lambda x: x[1],
            reverse=True
        )

        for index, score in ranked_results:
            if score <= 0:
                continue

            doc = self.documents[index]

            results.append({
                "chunk_id": doc["chunk_id"],
                "content": doc["content"],
                "metadata": doc,
                "score": float(score),
                "retrieval_type": "bm25"
            })

            if len(results) >= top_k:
                break

        return results