# -*- coding: utf-8 -*-
import sqlite3
import http.client
import json
import urllib.parse
from datetime import datetime, timezone, timedelta
from ..helpers.fixs_scrapper import FixsScrapper
from typing import Optional, Generator, Tuple
import time

DB_MODEL_VERSION = "nvd2.0-vulnscout1.1"


class NVD_DB:
    """
    A class to interact with sqlite local copy of NVD
    Also include API interaction used to build / refresh DB
    """

    def __init__(self, db_path: str, nvd_api_key: Optional[str] = None):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()

        self.last_modified: str = ""
        self.last_index: int = 0
        self.in_sync: bool = False

        self.nvd_api_key = nvd_api_key
        self.client: Optional[http.client.HTTPSConnection] = None
        self._init_db()

    def _init_db(self):
        """
        Initialize the local DB if it doesn't exist.
        """
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS nvd_vulns "
            + "(id TEXT PRIMARY KEY NOT NULL, published TEXT, lastModified TEXT, weaknesses TEXT, "
            + "versions_data TEXT, patch_url TEXT);"
        )
        self.cursor.execute("CREATE TABLE IF NOT EXISTS nvd_metadata (key TEXT PRIMARY KEY NOT NULL, value TEXT);")
        self.conn.commit()
        self._load_metadata()

    def _load_metadata(self):
        """
        Load the metadata from the local DB.
        """
        res = self.cursor.execute("SELECT value FROM nvd_metadata WHERE key = 'version';").fetchone()
        if res is None:
            # database was just created
            self.cursor.execute("INSERT INTO nvd_metadata (key, value) VALUES ('version', ?);", (DB_MODEL_VERSION,))
            self.conn.commit()
        elif res[0] != DB_MODEL_VERSION:
            # incompatible database version
            print("DB version mismatch, please update or reset the DB")
            raise Exception(f"DB version mismatch, expected {DB_MODEL_VERSION}, got {res[0]}")
        else:
            # database was existing before and with correct version, restore metadata
            res = self.cursor.execute("SELECT value FROM nvd_metadata WHERE key = 'last_index';").fetchone()
            if res is not None:
                self.last_index = int(res[0])

            # if restoring last_modified is impossible, then re-pull all data
            res = self.cursor.execute("SELECT value FROM nvd_metadata WHERE key = 'last_modified';").fetchone()
            try:
                if res is not None and datetime.fromisoformat(res[0]) is not None:
                    self.last_modified = res[0]
                else:
                    self.last_index = 0
            except Exception:
                self.last_index = 0

            print(
                "Restored DB from cache, last_index =",
                self.last_index,
                ", last_modified =",
                self.last_modified
            )

    def _call_nvd_api(self, params: dict = {}) -> Tuple[int, dict]:
        """
        Call the NVD API and return the status code as int and response as a dictionary.
        """
        if self.client is None:
            self.client = http.client.HTTPSConnection('services.nvd.nist.gov', 443)
        txt_params = "&".join(
            [
                f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}"
                for k, v in params.items()
            ]
        )
        headers = {
            'Content-Type': 'application/json'
        }
        if self.nvd_api_key is not None:
            headers['apiKey'] = self.nvd_api_key
        self.client.request("GET", f"/rest/json/cves/2.0?{txt_params}", headers=headers)
        resp = self.client.getresponse()
        try:
            return resp.status, json.loads(resp.read().decode())
        except json.decoder.JSONDecodeError:
            print("NVD API responded with invalid JSON. Adding an free NVD API key "
                  + f"can help to avoid this error. (status: {resp.status})", flush=True)
            return resp.status, {}
        except Exception as e:
            print(f"Error calling NVD API: {e}")
            raise e

    def api_get_cve(self, cve_id: str) -> Tuple[int, dict]:
        """
        Call the NVD API to get a specific CVE.
        """
        retry = 0
        status = 0
        while retry <= 3:
            time.sleep(10 * retry)
            status, data = self._call_nvd_api({"cveId": cve_id})
            if status == 200:
                return status, data
            else:
                retry += 1
        raise Exception(f"Failed to call NVD API (retry = 3, status = {status}, cveId = {cve_id})")

    def api_get_from_index(self, start_index: int = 0) -> Tuple[int, dict]:
        """
        Call the NVD API to get a list of CVEs starting from a specific index.
        """
        retry = 0
        status = 0
        while retry <= 3:
            time.sleep(10 * retry)
            status, data = self._call_nvd_api({"startIndex": str(start_index)})
            if status == 200:
                return status, data
            else:
                retry += 1
        raise Exception(f"Failed to call NVD API (retry = 3, status = {status}, startIndex = {start_index})")

    def api_get_by_date(self, start: str, end: str, index: int = 0) -> Tuple[int, dict]:
        """
        Call the NVD API to get a list of CVEs between specific date.
        """
        retry = 0
        status = 0
        while retry <= 3:
            time.sleep(10 * retry)
            status, data = self._call_nvd_api({
                "lastModStartDate": start,
                "lastModEndDate": end,
                "startIndex": str(index)
            })
            if status == 200:
                return status, data
            else:
                retry += 1
        raise Exception(f"Failed to call NVD API (retry = 3, status = {status}"
                        + f", startIndex = {index}, lastModStartDate = {start}, lastModEndDate = {end})")

    def api_weaknesses_to_list_str(self, weaknesses: list) -> list[str]:
        """
        Convert a list of weaknesses obtained from API to a string.
        """
        weaks = set([x["value"] for publisher in weaknesses for x in publisher["description"]])
        return list(weaks)

    def api_references_filter_patchs(self, references: list) -> list[str]:
        """
        Filter a list of references to get only the ones related to git patches.
        """
        return [x["url"] for x in references if "tags" in x and "Patch" in x["tags"]]

    def write_result_to_db(self, data: dict) -> bool:
        """
        Write the result of an API call to the local DB.
        """
        try:
            datas = []
            for vuln in data["vulnerabilities"]:
                cve = vuln["cve"]
                fix_scrapper = FixsScrapper()
                fix_scrapper.search_in_nvd(vuln)
                datas.append((
                    cve["id"],
                    cve["published"],
                    cve["lastModified"],
                    json.dumps(self.api_weaknesses_to_list_str(cve["weaknesses"])) if "weaknesses" in cve else "",
                    json.dumps(fix_scrapper.list_per_packages()),
                    json.dumps(self.api_references_filter_patchs(cve["references"])) if "references" in cve else ""
                ))
            self.cursor.executemany(
                "INSERT OR REPLACE INTO nvd_vulns "
                + "(id, published, lastModified, weaknesses, versions_data, patch_url) "
                + "VALUES (?, ?, ?, ?, ?, ?);",
                datas
            )
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Error writing to DB: {e}")
            raise e
        return False

    def build_initial_db(self) -> Generator:
        """
        Build the initial DB by calling the API and iterating on index.
        Writing the result to the local DB and yielding the last index and total results.
        """
        if self.last_index == 0:
            self.last_modified = datetime.now(timezone.utc).isoformat()
            self.cursor.execute(
                "INSERT OR REPLACE INTO nvd_metadata (key, value) VALUES ('last_modified', ?);",
                (self.last_modified,)
            )
            self.conn.commit()

        reached_end = False
        while not reached_end:
            status, data = self.api_get_from_index(self.last_index)
            if status != 200:
                raise Exception(f"Failed to fetch data from NVD API [{status}]", data)
            if self.write_result_to_db(data):
                self.last_index += len(data["vulnerabilities"])
                self.cursor.execute(
                    "INSERT OR REPLACE INTO nvd_metadata (key, value) VALUES ('last_index', ?);",
                    (str(self.last_index),)
                )
                self.conn.commit()
            yield self.last_index, data["totalResults"]
            reached_end = self.last_index >= data["totalResults"]

    def _find_120_days_interval(self, start: str, end: str) -> Tuple[str, str, bool]:
        """
        Take a start and end date as string in ISO datetime format.
        Return the start and end date to use in query and a boolean to true if end provided is end returned.
        """
        def clean(date: datetime) -> str:
            return date.isoformat().removesuffix("+00:00")

        st = datetime.fromisoformat(start) - timedelta(days=1)
        en = datetime.fromisoformat(end) + timedelta(days=1)
        delta = en - st
        if delta.days < 120:
            return (clean(st), clean(en), True)
        return (clean(st), clean(st + timedelta(days=119)), False)

    def update_db(self) -> Generator:
        """
        Update the local DB by calling the API using the last_modified date.
        Writing the result to the local DB and yielding the start and end time range pulled.
        """
        if self.last_modified == "":
            raise Exception("No last_modified date found in metadata, cannot update DB")
        reached_end = False
        while not reached_end:
            today = datetime.now(timezone.utc).isoformat()
            start, end, reached_end = self._find_120_days_interval(self.last_modified, today)

            reached_end_range = False
            current_index = 0
            while not reached_end_range:
                status, data = self.api_get_by_date(start, end, current_index)
                if status != 200:
                    raise Exception(f"Failed to fetch data from NVD API [{status}]", data)

                if self.write_result_to_db(data):
                    current_index += len(data["vulnerabilities"])
                yield f"{start} - {end} : {current_index} / {data['totalResults']}"
                reached_end_range = current_index >= data["totalResults"]

            self.last_modified = today if reached_end else end
            self.cursor.execute(
                "INSERT OR REPLACE INTO nvd_metadata (key, value) VALUES ('last_modified', ?);",
                (self.last_modified,)
            )
            self.conn.commit()
