from sentence_transformers import CrossEncoder


class Reranker:
    def __init__(self):

        self.model = CrossEncoder(
            "cross-encoder/ms-marco-MiniLM-L-6-v2"
        )

    def rank(self, query, results):
        if not results:
            return []

        pairs = [[query, doc["content"]] for doc in results]
        scores = self.model.predict(pairs)

        for doc, score in zip(results, scores):
            doc["rerank_score"] = float(score)

        results.sort(key=lambda x: x["rerank_score"], reverse=True)
        return results