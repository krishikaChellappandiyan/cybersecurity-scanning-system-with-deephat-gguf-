class MetadataBuilder:

    def build(
        self,
        source,
        title,
        chunk_id,
        url=None,
        severity="high",
        tags=None
    ):

        if tags is None:
            tags = []

        return {
            "source": source,
            "title": title,
            "chunk_id": chunk_id,
            "url": url,
            "severity": severity,
            "tags": tags
        }