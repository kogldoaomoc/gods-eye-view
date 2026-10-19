"""Per-case SQLite store with an R-tree index for bounding-box queries.

One database file per case. Entities accumulate observations and are never
overwritten; the same entity reported by several tools keeps every observation.
"""

from __future__ import annotations

import json
import re
import shutil
import sqlite3
import uuid
from pathlib import Path

from . import schema

_CASE_ID_RE = re.compile(r"^case_[a-z0-9]{12}$")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS entities (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  label TEXT NOT NULL,
  geo TEXT,
  attrs TEXT,
  hidden INTEGER NOT NULL DEFAULT 0,
  verified INTEGER NOT NULL DEFAULT 0,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS entities_type ON entities(type);
CREATE TABLE IF NOT EXISTS observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entity_id TEXT NOT NULL,
  tool TEXT NOT NULL,
  tool_version TEXT,
  query TEXT NOT NULL,
  at TEXT NOT NULL,
  confidence REAL NOT NULL,
  raw TEXT,
  UNIQUE(entity_id, tool, query, at)
);
CREATE INDEX IF NOT EXISTS observations_entity ON observations(entity_id);
CREATE TABLE IF NOT EXISTS links (
  id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  target TEXT NOT NULL,
  relation TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS links_source ON links(source);
CREATE INDEX IF NOT EXISTS links_target ON links(target);
CREATE VIRTUAL TABLE IF NOT EXISTS entity_rtree USING rtree(rowid, min_lon, max_lon, min_lat, max_lat);
CREATE TABLE IF NOT EXISTS rtree_map (entity_id TEXT PRIMARY KEY, rowid INTEGER NOT NULL);
"""


class CaseStore:
    """SQLite-backed store for one case."""

    def __init__(self, db_path: Path):
        self.path = Path(db_path)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # -- metadata -----------------------------------------------------------
    def set_meta(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self._conn.commit()

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        row = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    # -- ingestion ----------------------------------------------------------
    def ingest(self, entities: list[dict], links: list[dict], observation: dict) -> dict:
        """Merge a batch into the case. Returns counts of new/updated records."""
        new_entities = 0
        updated = 0
        for entity in entities:
            if self._upsert_entity(entity, observation):
                new_entities += 1
            else:
                updated += 1
        for link in links:
            self._conn.execute(
                "INSERT OR IGNORE INTO links(id, source, target, relation) VALUES(?, ?, ?, ?)",
                (link["id"], link["source"], link["target"], link["relation"]),
            )
        self._conn.commit()
        return {"entities": new_entities, "updated": updated, "links": len(links)}

    def _upsert_entity(self, entity: dict, observation: dict) -> bool:
        at = observation["at"]
        existing = self._conn.execute(
            "SELECT id, geo FROM entities WHERE id=?", (entity["id"],)
        ).fetchone()
        geo = entity.get("geo")
        is_new = existing is None
        if is_new:
            self._conn.execute(
                "INSERT INTO entities(id, type, value, label, geo, attrs, first_seen, last_seen)"
                " VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entity["id"],
                    entity["type"],
                    entity["value"],
                    entity["label"],
                    json.dumps(geo) if geo else None,
                    json.dumps(entity["attrs"]) if entity.get("attrs") else None,
                    at,
                    at,
                ),
            )
        else:
            self._conn.execute("UPDATE entities SET last_seen=? WHERE id=?", (at, entity["id"]))
            # Keep the first good geo; a later, more precise one replaces it.
            if geo and _geo_is_better(geo, json.loads(existing["geo"]) if existing["geo"] else None):
                self._conn.execute(
                    "UPDATE entities SET geo=? WHERE id=?", (json.dumps(geo), entity["id"])
                )
        if geo and "lat" in geo:
            self._index_geo(entity["id"], geo)
        self._conn.execute(
            "INSERT OR IGNORE INTO observations(entity_id, tool, tool_version, query, at, confidence, raw)"
            " VALUES(?, ?, ?, ?, ?, ?, ?)",
            (
                entity["id"],
                observation["tool"],
                observation.get("toolVersion"),
                observation["query"],
                at,
                observation["confidence"],
                observation.get("raw"),
            ),
        )
        return is_new

    def _index_geo(self, entity_id: str, geo: dict) -> None:
        lat, lon = geo["lat"], geo["lon"]
        row = self._conn.execute(
            "SELECT rowid FROM rtree_map WHERE entity_id=?", (entity_id,)
        ).fetchone()
        if row:
            self._conn.execute(
                "UPDATE entity_rtree SET min_lon=?, max_lon=?, min_lat=?, max_lat=? WHERE rowid=?",
                (lon, lon, lat, lat, row["rowid"]),
            )
            return
        cursor = self._conn.execute(
            "INSERT INTO entity_rtree(min_lon, max_lon, min_lat, max_lat) VALUES(?, ?, ?, ?)",
            (lon, lon, lat, lat),
        )
        self._conn.execute(
            "INSERT INTO rtree_map(entity_id, rowid) VALUES(?, ?)", (entity_id, cursor.lastrowid)
        )

    # -- queries ------------------------------------------------------------
    def query_entities(
        self,
        *,
        bbox: tuple[float, float, float, float] | None = None,
        types: list[str] | None = None,
        min_confidence: float = 0.0,
        text: str | None = None,
        include_hidden: bool = False,
        limit: int = 2000,
    ) -> list[dict]:
        clauses = []
        params: list = []
        if bbox:
            min_lon, min_lat, max_lon, max_lat = bbox
            clauses.append(
                "e.id IN (SELECT m.entity_id FROM rtree_map m JOIN entity_rtree r ON m.rowid=r.rowid"
                " WHERE r.min_lon<=? AND r.max_lon>=? AND r.min_lat<=? AND r.max_lat>=?)"
            )
            params += [max_lon, min_lon, max_lat, min_lat]
        if types:
            clauses.append("e.type IN (%s)" % ",".join("?" * len(types)))
            params += types
        if not include_hidden:
            clauses.append("e.hidden=0")
        if text:
            clauses.append("(e.value LIKE ? OR e.label LIKE ?)")
            params += [f"%{text}%", f"%{text}%"]
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self._conn.execute(
            f"SELECT e.* FROM entities e{where} ORDER BY e.last_seen DESC LIMIT ?",
            (*params, max(1, min(limit, 10000))),
        ).fetchall()
        result = []
        for row in rows:
            confidence = self._max_confidence(row["id"])
            if confidence < min_confidence:
                continue
            result.append(self._row_to_entity(row, confidence))
        return result

    def get_entity(self, entity_id: str) -> dict | None:
        row = self._conn.execute("SELECT * FROM entities WHERE id=?", (entity_id,)).fetchone()
        if not row:
            return None
        entity = self._row_to_entity(row, self._max_confidence(entity_id))
        entity["observations"] = [
            {
                "tool": obs["tool"],
                "toolVersion": obs["tool_version"],
                "query": obs["query"],
                "at": obs["at"],
                "confidence": obs["confidence"],
                "raw": obs["raw"],
            }
            for obs in self._conn.execute(
                "SELECT * FROM observations WHERE entity_id=? ORDER BY at", (entity_id,)
            ).fetchall()
        ]
        entity["links"] = [
            dict(link)
            for link in self._conn.execute(
                "SELECT id, source, target, relation FROM links WHERE source=? OR target=?",
                (entity_id, entity_id),
            ).fetchall()
        ]
        return entity

    def set_flag(self, entity_id: str, *, hidden: bool | None = None, verified: bool | None = None) -> bool:
        sets = []
        params: list = []
        if hidden is not None:
            sets.append("hidden=?")
            params.append(1 if hidden else 0)
        if verified is not None:
            sets.append("verified=?")
            params.append(1 if verified else 0)
        if not sets:
            return False
        params.append(entity_id)
        cursor = self._conn.execute(f"UPDATE entities SET {', '.join(sets)} WHERE id=?", params)
        self._conn.commit()
        return cursor.rowcount > 0

    def counts(self) -> dict:
        rows = self._conn.execute("SELECT type, COUNT(*) AS n FROM entities WHERE hidden=0 GROUP BY type").fetchall()
        return {row["type"]: row["n"] for row in rows}

    def _max_confidence(self, entity_id: str) -> float:
        row = self._conn.execute(
            "SELECT MAX(confidence) AS c FROM observations WHERE entity_id=?", (entity_id,)
        ).fetchone()
        return float(row["c"]) if row and row["c"] is not None else 0.0

    @staticmethod
    def _row_to_entity(row: sqlite3.Row, confidence: float) -> dict:
        entity = {
            "id": row["id"],
            "type": row["type"],
            "value": row["value"],
            "label": row["label"],
            "confidence": round(confidence, 3),
            "hidden": bool(row["hidden"]),
            "verified": bool(row["verified"]),
            "firstSeen": row["first_seen"],
            "lastSeen": row["last_seen"],
        }
        if row["geo"]:
            entity["geo"] = json.loads(row["geo"])
        if row["attrs"]:
            entity["attrs"] = json.loads(row["attrs"])
        return entity


def _geo_is_better(candidate: dict, current: dict | None) -> bool:
    if current is None:
        return True
    order = {p: i for i, p in enumerate(schema.PRECISIONS)}
    return order.get(candidate.get("precision"), 99) < order.get(current.get("precision"), 99)


class CaseRegistry:
    """Creates and opens case stores under one directory."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._open: dict[str, CaseStore] = {}

    def create(self, name: str) -> dict:
        case_id = "case_" + uuid.uuid4().hex[:12]
        store = self._store(case_id)
        store.set_meta("id", case_id)
        store.set_meta("name", name.strip() or case_id)
        store.set_meta("created", schema.now_iso())
        return self.describe(case_id)

    def list_cases(self) -> list[dict]:
        cases = []
        for path in sorted(self.root.glob("case_*.sqlite")):
            case_id = path.stem
            if _CASE_ID_RE.match(case_id):
                cases.append(self.describe(case_id))
        return cases

    def describe(self, case_id: str) -> dict:
        store = self._store(case_id)
        return {
            "id": case_id,
            "name": store.get_meta("name", case_id),
            "created": store.get_meta("created"),
            "counts": store.counts(),
        }

    def store(self, case_id: str) -> CaseStore:
        if not _CASE_ID_RE.match(case_id):
            raise ValueError(f"invalid case id: {case_id!r}")
        if not (self.root / f"{case_id}.sqlite").exists():
            raise KeyError(case_id)
        return self._store(case_id)

    def raw_dir(self, case_id: str) -> Path:
        self.store(case_id)
        path = self.root / case_id / "raw"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def delete(self, case_id: str) -> bool:
        if not _CASE_ID_RE.match(case_id):
            raise ValueError(f"invalid case id: {case_id!r}")
        store = self._open.pop(case_id, None)
        if store:
            store.close()
        removed = False
        for suffix in (".sqlite", ".sqlite-wal", ".sqlite-shm"):
            path = self.root / f"{case_id}{suffix}"
            if path.exists():
                path.unlink()
                removed = True
        case_dir = self.root / case_id
        if case_dir.exists():
            shutil.rmtree(case_dir)
            removed = True
        return removed

    def _store(self, case_id: str) -> CaseStore:
        if not _CASE_ID_RE.match(case_id):
            raise ValueError(f"invalid case id: {case_id!r}")
        if case_id not in self._open:
            self._open[case_id] = CaseStore(self.root / f"{case_id}.sqlite")
        return self._open[case_id]

    def close(self) -> None:
        for store in self._open.values():
            store.close()
        self._open.clear()
