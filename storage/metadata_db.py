import sqlite3
from config import METADATA_DB_PATH


class MetadataDB:
    def __init__(self, rebuild=False):
        METADATA_DB_PATH.mkdir(parents=True, exist_ok=True)

        self.db_path = METADATA_DB_PATH / "metadata.db"

        if rebuild and self.db_path.exists():
            self.db_path.unlink()
            print(f"Deleted old metadata DB: {self.db_path}")

        self.connection = sqlite3.connect(self.db_path)
        self._create_table()

    def _create_table(self):
        cursor = self.connection.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS metadata (
            chunk_id TEXT PRIMARY KEY,
            source TEXT,
            title TEXT,
            url TEXT,
            content TEXT,
            severity TEXT,
            tags TEXT
        )
        """)

        self.connection.commit()
        cursor.close()

    def insert(self, metadata):
        cursor = self.connection.cursor()

        cursor.execute("""
        INSERT OR REPLACE INTO metadata
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            metadata.get("chunk_id"),
            metadata.get("source"),
            metadata.get("title"),
            metadata.get("url"),
            metadata.get("content"),
            metadata.get("severity"),
            ",".join(metadata.get("tags", []))
        ))

        self.connection.commit()
        cursor.close()

    def fetch(self, chunk_id):
        cursor = self.connection.cursor()

        cursor.execute("""
        SELECT * FROM metadata WHERE chunk_id = ?
        """, (chunk_id,))

        result = cursor.fetchone()
        cursor.close()

        return result

    def fetch_all(self):
        cursor = self.connection.cursor()

        cursor.execute("""
        SELECT
            chunk_id,
            source,
            title,
            url,
            content,
            severity,
            tags
        FROM metadata
        """)

        rows = cursor.fetchall()
        cursor.close()

        documents = []

        for row in rows:
            documents.append({
                "chunk_id": row[0],
                "source": row[1],
                "title": row[2],
                "url": row[3],
                "content": row[4],
                "severity": row[5],
                "tags": row[6].split(",") if row[6] else []
            })

        return documents

    def close(self):
        self.connection.close()