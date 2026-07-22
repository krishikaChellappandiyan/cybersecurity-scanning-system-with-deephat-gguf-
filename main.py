"""
DeepHat Cybersecurity Assistant - RAG enabled, with support for uploading
a JSON file mid-conversation.

Commands available at the "You :" prompt:
    upload <path-to-file.json>   - load a JSON file to ground answers in
    unload                       - drop the currently uploaded file
    quit / exit                  - end the chat

Accepted JSON shapes for an uploaded file:

    # list of documents
    [
        {"title": "...", "content": "..."},
        {"id": "CVE-2024-12345", "summary": "..."}   # cve-style also accepted
    ]

    # single document
    {"title": "...", "content": "..."}

    # plain strings
    ["some raw text", "more raw text"]
"""

import json
import numpy as np

from deephat import DeepHat
from retrieval.retriever import Retriever
from context.context_builder import ContextBuilder
from processing.cleaner import TextCleaner
from processing.chunker import TextChunker
from embedding.embedder import Embedder


def load_uploaded_documents(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        data = [data]

    documents = []
    for i, item in enumerate(data):
        if isinstance(item, str):
            documents.append({"title": f"uploaded_doc_{i}", "content": item})
        elif isinstance(item, dict):
            content = item.get("content") or item.get("summary") or item.get("text")
            title = item.get("title") or item.get("id") or f"uploaded_doc_{i}"
            if not content:
                continue
            documents.append({"title": title, "content": content})

    return documents


class UploadedIndex:
    """Small in-memory vector index over just the uploaded file's content.
    Never written to disk - lives only for the current chat session."""

    def __init__(self, documents, embedder):
        cleaner = TextCleaner()
        chunker = TextChunker()
        self.embedder = embedder

        self.chunks = []
        self.payloads = []

        for doc in documents:
            cleaned = cleaner.clean(doc["content"])
            for chunk in chunker.chunk(cleaned):
                self.chunks.append(chunk)
                self.payloads.append({
                    "content": chunk,
                    "url": f"uploaded:{doc['title']}",
                    "source": "uploaded_file"
                })

        if self.chunks:
            self.vectors = np.array(self.embedder.encode(self.chunks), dtype="float32")
        else:
            self.vectors = np.zeros((0, 768), dtype="float32")

    def search(self, query, top_k=3):
        if len(self.chunks) == 0:
            return []

        query_vec = np.array(self.embedder.encode([query])[0], dtype="float32")
        scores = self.vectors @ query_vec  # cosine similarity - vectors are normalized

        top_indices = np.argsort(scores)[::-1][:top_k]

        results = []
        for idx in top_indices:
            payload = dict(self.payloads[idx])
            payload["score"] = float(scores[idx])
            payload["retrieval_type"] = "uploaded_file"
            results.append(payload)

        return results


def main():
    bot = DeepHat()
    kb_retriever = Retriever()
    context_builder = ContextBuilder()
    embedder = Embedder()

    uploaded_index = None  # set once the user runs "upload <file>"

    print("=" * 60)
    print(" DeepHat Cybersecurity Assistant (RAG-enabled)")
    print(" Type 'upload <file.json>' to ground answers in a file.")
    print("=" * 60)

    while True:

        prompt = input("\nYou : ").strip()

        if not prompt:
            continue

        if prompt.lower() in ["quit", "exit"]:
            break

        if prompt.lower().startswith("upload "):
            file_path = prompt[len("upload "):].strip().strip('"')
            try:
                documents = load_uploaded_documents(file_path)
                uploaded_index = UploadedIndex(documents, embedder)
                print(f"\nLoaded {len(documents)} document(s), "
                      f"{len(uploaded_index.chunks)} chunk(s) indexed from {file_path}")
            except FileNotFoundError:
                print(f"\nFile not found: {file_path}")
            except json.JSONDecodeError as e:
                print(f"\nCouldn't parse {file_path} as JSON: {e}")
            continue

        if prompt.lower() == "unload":
            uploaded_index = None
            print("\nUploaded file cleared - back to knowledge-base-only answers.")
            continue

        uploaded_results = uploaded_index.search(prompt, top_k=3) if uploaded_index else []
        kb_results = kb_retriever.retrieve(query=prompt, top_k=5) or []

        combined = uploaded_results + kb_results

        if combined:
            context = context_builder.build(combined)
            print(f"\n[Retrieved {len(uploaded_results)} chunk(s) from your uploaded file "
                  f"+ {len(kb_results)} chunk(s) from the knowledge base]")
            for doc in combined:
                print(f"  - {doc.get('url')}")
        else:
            context = ""
            print("\n[No relevant context found — answering from general knowledge]")

        answer = bot.chat(prompt, context=context)

        print("\nDeepHat :\n")
        print(answer)


if __name__ == "__main__":
    main()