class ContextBuilder:
    def build(self, retrieved_docs):
        context_parts = []
        for doc in retrieved_docs:
            context_parts.append(
                doc["url"] + "\n" + doc["content"]
            )
        return "\n\n".join(context_parts)