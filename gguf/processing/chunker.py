class TextChunker:
    def chunk(self, text: str):
        chunks=[]
        start=0
        CHUNK_SIZE = 500
        CHUNK_OVERLAP = 100
        while start<len(text):
            end=start+CHUNK_SIZE
            chunk=text[start:end]
            chunks.append(chunk)
            start+=CHUNK_SIZE-CHUNK_OVERLAP
        return chunks