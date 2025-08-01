import sqlite3
import csv
import urllib.request
import gzip
from datetime import datetime

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


class EPSS_DB:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self._init_db()

    def _init_db(self):
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS epss_scores (
                cve TEXT PRIMARY KEY NOT NULL,
                epss REAL,
                percentile REAL
            )
        """)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS epss_metadata (
                key TEXT PRIMARY KEY NOT NULL,
                value TEXT
            )
        """)
        self.conn.commit()

    def update_epss(self):
        tmp_gz = "/tmp/epss.csv.gz"
        urllib.request.urlretrieve(EPSS_URL, tmp_gz)

        with gzip.open(tmp_gz, "rt") as f:
            next(f)
            reader = csv.DictReader(f)
            rows = [(row['cve'], float(row['epss']), float(row['percentile'])) for row in reader if row['cve'].startswith("CVE")]

        self.cursor.execute("DELETE FROM epss_scores")
        self.cursor.executemany(
            "INSERT OR REPLACE INTO epss_scores (cve, epss, percentile) VALUES (?, ?, ?);",
            rows
        )
        self.cursor.execute(
            "INSERT OR REPLACE INTO epss_metadata (key, value) VALUES ('last_updated', ?);",
            (datetime.utcnow().isoformat(),)
        )
        self.conn.commit()

    def get_score(self, cve_id: str):
        row = self.cursor.execute(
            "SELECT epss, percentile FROM epss_scores WHERE cve = ?;",
            (cve_id,)
        ).fetchone()
        if row:
            return {"score": row[0], "percentile": row[1]}
        return None

    def needs_update(self, days: int = 1) -> bool:
        res = self.cursor.execute(
            "SELECT value FROM epss_metadata WHERE key = 'last_updated';"
        ).fetchone()
        if not res:
            return True
        try:
            last_updated = datetime.fromisoformat(res[0])
            return (datetime.utcnow() - last_updated).days >= days
        except Exception:
            return True
