import sqlite3
import csv
import urllib.request
import gzip
from datetime import datetime
import os

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

        # Set up proxy handler if proxy environment variables are set
        proxies = {}
        if os.getenv('HTTP_PROXY') or os.getenv('http_proxy'):
            proxies['http'] = os.getenv('HTTP_PROXY') or os.getenv('http_proxy')
        if os.getenv('HTTPS_PROXY') or os.getenv('https_proxy'):
            proxies['https'] = os.getenv('HTTPS_PROXY') or os.getenv('https_proxy')

        if proxies:
            proxy_handler = urllib.request.ProxyHandler(proxies)
            opener = urllib.request.build_opener(proxy_handler)
            urllib.request.install_opener(opener)

        urllib.request.urlretrieve(EPSS_URL, tmp_gz)

        with gzip.open(tmp_gz, "rt") as f:
            while True:
                pos = f.tell()
                line = f.readline()
                if not line:
                    raise ValueError("No valid header found in the CSV file")
                lower_line = line.strip().lower()
                if 'cve' in lower_line and 'epss' in lower_line and 'percentile' in lower_line:
                    f.seek(pos)
                    break

            reader = csv.DictReader(f, skipinitialspace=True)
            rows = []
            for row in reader:
                cve = row.get('cve') or row.get('CVE')
                epss = row.get('epss')
                percentile = row.get('percentile')
                if cve and cve.startswith("CVE") and epss and percentile:
                    try:
                        rows.append((cve, float(epss), float(percentile)))
                    except ValueError:
                        continue

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
