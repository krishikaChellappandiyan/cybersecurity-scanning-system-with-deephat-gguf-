import os
from sentence_transformers import SentenceTransformer


class Embedder:
    def __init__(self):

        self.model = SentenceTransformer(
            "intfloat/e5-base-v2"
        )

    def encode(self, texts):
        return self.model.encode(
            texts,
            normalize_embeddings=True,
            convert_to_numpy=True,
            batch_size=8,
            show_progress_bar=True
        )