"""The Erasure Illusion - reproducing soft-delete residue in Chroma.

Report #2 (August 2026), Week-1 data run. Deterministic: same seed, same
numbers on every run.

What it does, in order:
  A. builds a synthetic Australian dental-clinic knowledge base (2,000 patient
     records, free-text clinical notes carrying name / DOB / phone / email /
     Medicare / address) and loads it into a persistent Chroma collection,
     exactly the way a RAG quick-start wires one up
  B. processes 100 erasure requests with collection.delete(ids=...) - the call
     every "handle a right-to-be-forgotten request" tutorial tells you to make
  C. verifies at the API level that those 100 people are gone, then restarts
     the client and verifies again
  D. goes to the storage layer and looks for them anyway:
       chroma.sqlite3               - write-ahead log, freed pages
       <segment>/data_level0.bin    - the HNSW index file
  E. tries to re-identify the erased people from the recovered vectors alone,
     with only a name (and a name + date of birth) as attacker knowledge
  F. tests mitigations honestly: continued writes, vacuum, delete_collection

Rerun (durable paths):
  C:\\Users\\Belle\\au-pr-niv-plan\\reports\\tools\\chromaenv\\Scripts\\python.exe
    C:\\Users\\Belle\\au-pr-niv-plan\\reports\\findings\\src\\chroma_erasure.py

Environment: reports/tools/requirements-chroma.txt
No real patient data is used anywhere. Every identifier is fabricated.
"""

from __future__ import annotations

import gc
import json
import os
import random
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile

import numpy as np

import chromadb
from chromadb.utils import embedding_functions

SEED = 20260801
N_PATIENTS = 2000       # a plausible small-clinic knowledge base
N_ERASED = 100          # 5% of the book asks to be forgotten
N_FOLLOW_ON_WRITES = 1500   # more than Chroma's default sync_threshold of 1000
HERE = os.path.dirname(os.path.abspath(__file__))
# optional run tag, so repeat runs can be kept side by side as evidence of
# stability: `python chroma_erasure.py run2` -> erasure-2026-08-raw-run2.json
_TAG = sys.argv[1] if len(sys.argv) > 1 else ""
OUT_JSON = os.path.join(os.path.dirname(HERE),
                        f"erasure-2026-08-raw{'-' + _TAG if _TAG else ''}.json")

R: dict = {}


# --------------------------------------------------------------------------
# fixture - a synthetic AU dental clinic
# --------------------------------------------------------------------------

GIVEN = ["Mia", "Oliver", "Charlotte", "Noah", "Amelia", "Jack", "Isla", "Leo",
         "Grace", "Henry", "Ruby", "Lucas", "Chloe", "Ethan", "Zoe", "Hugo",
         "Ava", "Liam", "Harper", "Max", "Ella", "Owen", "Lily", "Finn",
         "Sienna", "Archie", "Willow", "Theo", "Poppy", "Jasper", "Nina",
         "Caleb", "Freya", "Elias", "Maeve", "Rafferty", "Anika", "Dashiell",
         "Imogen", "Rory", "Priya", "Callum", "Marguerite", "Tobias", "Esme",
         "Xavier", "Delphine", "Hamish", "Saoirse", "Emeka", "Wren", "Soren",
         "Talia", "Bodhi", "Clementine", "Ignatius", "Nadia", "Fergus",
         "Beatrix", "Kwame"]
FAMILY = ["Nguyen", "Chen", "O'Brien", "Kaur", "Papadopoulos", "Smith", "Tran",
          "Kelly", "Singh", "Rossi", "Muller", "Yilmaz", "Watson", "Patel",
          "Fitzgerald", "Zhang", "Kowalski", "Andersen", "Rahman", "Costa",
          "Whitlam", "Hemsworth", "Barrett", "Novak", "Silva", "Dimitriou",
          "Hollis", "Marchetti", "Okafor", "Lindqvist", "Baptiste", "Aluko",
          "Kirkbride", "Sowerby", "Vasquez", "Haldane", "Petrossian",
          "Featherstone", "Abernethy", "Castellano"]
STREETS = ["Barkly St", "Glenferrie Rd", "Sydney Rd", "Chapel St", "Toorak Rd",
           "Burke Rd", "High St", "Riversdale Rd", "Nicholson St", "Rathdowne St",
           "Lygon St", "Smith St", "Oxford St", "Given Tce", "Rundle St"]
SUBURBS = [("Brunswick", "VIC", "3056"), ("Hawthorn", "VIC", "3122"),
           ("Newtown", "NSW", "2042"), ("Fortitude Valley", "QLD", "4006"),
           ("Norwood", "SA", "5067"), ("Subiaco", "WA", "6008"),
           ("Sandy Bay", "TAS", "7005"), ("Braddon", "ACT", "2612")]
COMPLAINTS = [
    "presented with sensitivity in the lower left quadrant",
    "attended for a six-month scale and clean",
    "reported pain on biting, suspected cracked cusp",
    "reviewed for orthodontic retainer fit",
    "emergency appointment after a chipped incisor",
    "consultation regarding wisdom tooth removal",
    "follow-up after root canal therapy on tooth 26",
    "assessment for implant suitability, upper right",
    "routine radiographs, no new caries identified",
    "reported grinding at night, discussed a splint",
]
PLANS = [
    "Booked for a composite restoration next Tuesday.",
    "Referred to an oral surgeon; patient anxious about sedation.",
    "Discussed payment plan; patient is on a health care card.",
    "Advised fluoride varnish and a review in three months.",
    "Prescribed amoxicillin, 500mg, and scheduled a recall.",
    "Declined treatment on cost grounds; note for follow-up call.",
]


def medicare_number(rng: random.Random) -> str:
    """A Medicare-shaped number with a valid check digit, printed the usual way."""
    body = [rng.randint(2, 6)] + [rng.randint(0, 9) for _ in range(7)]
    weights = [1, 3, 7, 9, 1, 3, 7, 9]
    check = sum(d * w for d, w in zip(body, weights)) % 10
    issue = rng.randint(1, 9)
    d = "".join(str(x) for x in body) + str(check)   # 8 digits + check digit
    return f"{d[:4]} {d[4:9]} {issue}"               # printed 4-5-1, issue number last


def build_patients() -> list[dict]:
    rng = random.Random(SEED)
    # every patient gets a distinct name, so a name can identify exactly one
    # record; see the caveats note about real rosters, where names repeat
    combos = [f"{g} {f}" for g in GIVEN for f in FAMILY]
    assert len(combos) >= N_PATIENTS, "name pool too small for unique names"
    rng.shuffle(combos)
    names = combos[:N_PATIENTS]
    out = []
    for i in range(N_PATIENTS):
        name = names[i]
        suburb, state, postcode = rng.choice(SUBURBS)
        dob = f"{rng.randint(1, 28):02d}/{rng.randint(1, 12):02d}/{rng.randint(1948, 2008)}"
        first, last = name.split()
        rec = {
            "pid": f"PT-{i:05d}",
            "name": name,
            "dob": dob,
            "phone": f"04{rng.randint(10, 99)} {rng.randint(100, 999)} {rng.randint(100, 999)}",
            "email": f"{first.lower()}.{last.lower().replace(chr(39), '')}"
                     f"@{rng.choice(['gmail.com', 'outlook.com', 'bigpond.com'])}",
            "medicare": medicare_number(rng),
            "address": f"{rng.randint(1, 240)} {rng.choice(STREETS)}, {suburb} {state} {postcode}",
        }
        rec["note"] = (
            f"Patient {rec['name']} (DOB {rec['dob']}, Medicare {rec['medicare']}) "
            f"{rng.choice(COMPLAINTS)}. Contact {rec['phone']} or {rec['email']}. "
            f"Address on file: {rec['address']}. {rng.choice(PLANS)}"
        )
        out.append(rec)
    return out


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def close_chroma():
    """Release handles so the store can be copied on Windows."""
    try:
        chromadb.api.client.SharedSystemClient.clear_system_cache()
    except Exception:
        pass
    gc.collect()


def file_inventory(root: str) -> dict:
    inv = {}
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            p = os.path.join(dirpath, fn)
            inv[os.path.relpath(p, root).replace("\\", "/")] = os.path.getsize(p)
    return inv


def segment_dir(root: str):
    for entry in sorted(os.listdir(root)):
        p = os.path.join(root, entry)
        if os.path.isdir(p) and os.path.exists(os.path.join(p, "data_level0.bin")):
            return p
    return None


def byte_hits(root: str, needles: dict) -> dict:
    out: dict = {}
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            p = os.path.join(dirpath, fn)
            with open(p, "rb") as fh:
                blob = fh.read()
            rel = os.path.relpath(p, root).replace("\\", "/")
            for label, needle in needles.items():
                c = blob.count(needle)
                if c:
                    out.setdefault(label, {})[rel] = c
    return out


def sqlite_state(db_path: str) -> dict:
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    info = {}
    try:
        info["tables"] = {}
        for (t,) in cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
            try:
                info["tables"][t] = cur.execute(f"SELECT COUNT(*) FROM '{t}'").fetchone()[0]
            except Exception as e:
                info["tables"][t] = f"ERR {e}"
        info["embeddings_queue_columns"] = [
            r[1] for r in cur.execute("PRAGMA table_info(embeddings_queue)")]
        try:
            info["operations"] = dict(cur.execute(
                "SELECT operation, COUNT(*) FROM embeddings_queue GROUP BY operation"
            ).fetchall())
        except Exception as e:
            info["operations"] = f"ERR {e}"
        try:
            rows = list(cur.execute("SELECT * FROM embeddings_queue_config"))
            info["embeddings_queue_config"] = [
                dict(zip([d[0] for d in cur.description], r)) for r in rows]
        except Exception as e:
            info["embeddings_queue_config"] = f"ERR {e}"
    finally:
        con.close()
    return info


def _as_text(v) -> str:
    if v is None:
        return ""
    return v if isinstance(v, str) else v.decode("utf-8", "replace")


def wal_recover(db_path: str, erased_ids: list) -> dict:
    """One SELECT against the WAL - what actually comes back for an erased person?

    Chroma's embeddings_queue rows carry an `operation` code; a surviving ADD row
    (with its vector and document) is a real residue, a DELETE tombstone is not.
    """
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    res = {"records_with_any_wal_row": 0, "records_with_surviving_add_row": 0,
           "records_with_vector_in_wal": 0, "records_with_document_text_in_wal": 0,
           "operation_codes_seen": {}, "samples": {}}
    try:
        cols = [r[1] for r in cur.execute("PRAGMA table_info(embeddings_queue)")]
        if "id" not in cols:
            return {"error": "no id column in embeddings_queue", "columns": cols}
        has_vec, has_meta = "vector" in cols, "metadata" in cols
        for n, eid in enumerate(erased_ids):
            rows = cur.execute(
                f"SELECT operation, {'vector' if has_vec else 'NULL'}, "
                f"{'metadata' if has_meta else 'NULL'} "
                f"FROM embeddings_queue WHERE id=?", (eid,)).fetchall()
            if not rows:
                continue
            res["records_with_any_wal_row"] += 1
            got_vec = got_txt = got_add = False
            for op, vec, meta in rows:
                res["operation_codes_seen"][str(op)] = \
                    res["operation_codes_seen"].get(str(op), 0) + 1
                if vec:
                    got_vec = True
                txt = _as_text(meta).strip()
                if txt and txt not in ("{}", "null"):
                    got_txt = True
                if vec or (txt and txt not in ("{}", "null")):
                    got_add = True
            res["records_with_surviving_add_row"] += got_add
            res["records_with_vector_in_wal"] += got_vec
            res["records_with_document_text_in_wal"] += got_txt
            if n < 2:
                res["samples"][eid] = {
                    "operations": [r[0] for r in rows],
                    "vector_bytes": next((len(r[1]) for r in rows if r[1]), 0),
                    "metadata_first_240_chars": next(
                        (_as_text(r[2])[:240] for r in rows if _as_text(r[2])), ""),
                }
    finally:
        con.close()
    return res


def _all_text_columns(cur) -> list:
    """Every (table, column) pair in the database, so nothing is left unprobed."""
    pairs = []
    for (t,) in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
        try:
            for r in cur.execute(f"PRAGMA table_info('{t}')"):
                pairs.append((t, r[1]))
        except Exception:
            continue
    return pairs


def live_sql_hits(db_path: str, needle: str) -> dict:
    """Is the string reachable through an ordinary SQL query on ANY live table?

    Scans every column of every table rather than a hand-picked few, so a "not
    reachable by SELECT" result means what it says.
    """
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    out = {}
    try:
        for t, c in _all_text_columns(cur):
            try:
                n = cur.execute(
                    f"SELECT COUNT(*) FROM '{t}' WHERE CAST(\"{c}\" AS TEXT) LIKE ?",
                    (f"%{needle}%",)).fetchone()[0]
            except Exception:
                continue          # virtual/shadow columns that reject CAST
            if n:
                out[f"{t}.{c}"] = n
    finally:
        con.close()
    return out


def freelist_pages(db_path: str) -> tuple:
    """Walk the SQLite freelist and return (set_of_free_page_numbers, page_size).

    Header: page size at byte 16, first freelist trunk page at 32, free page
    count at 36. Each trunk page is [next trunk (4B)][leaf count (4B)][leaves...].
    Page numbers are 1-based.
    """
    with open(db_path, "rb") as fh:
        blob = fh.read()
    if len(blob) < 100 or blob[:15] != b"SQLite format 3":
        return set(), 0
    page_size = int.from_bytes(blob[16:18], "big")
    if page_size == 1:
        page_size = 65536
    trunk = int.from_bytes(blob[32:36], "big")
    declared = int.from_bytes(blob[36:40], "big")
    free, seen = set(), set()
    while trunk and trunk not in seen:
        seen.add(trunk)
        free.add(trunk)
        base = (trunk - 1) * page_size
        if base + 8 > len(blob):
            break
        nxt = int.from_bytes(blob[base:base + 4], "big")
        n_leaves = int.from_bytes(blob[base + 4:base + 8], "big")
        for k in range(min(n_leaves, (page_size - 8) // 4)):
            off = base + 8 + k * 4
            if off + 4 > len(blob):
                break
            leaf = int.from_bytes(blob[off:off + 4], "big")
            if leaf:
                free.add(leaf)
        trunk = nxt
    return free, page_size, declared


def residue_in_free_pages(db_path: str, needles: dict) -> dict:
    """For each needle byte-present in the DB file, is it inside a freed page?

    This is the measurement behind the 'residue sits in freed pages' claim -
    a freelist walk, not an inference from failed SELECTs.
    """
    free, page_size, declared = freelist_pages(db_path)
    with open(db_path, "rb") as fh:
        blob = fh.read()
    only_free = only_allocated = mixed = absent = 0
    detail = {}
    for label, needle in needles.items():
        offsets, start = [], 0
        while True:
            i = blob.find(needle, start)
            if i < 0:
                break
            offsets.append(i)
            start = i + 1
        if not offsets:
            absent += 1
            continue
        pages = {o // page_size + 1 for o in offsets}
        f, a = pages & free, pages - free
        if f and not a:
            only_free += 1
        elif a and not f:
            only_allocated += 1
        else:
            mixed += 1
        if len(detail) < 3:
            detail[label] = {"occurrences": len(offsets),
                             "pages": sorted(pages),
                             "free_pages_hit": sorted(f)}
    # the four categories are disjoint and sum to len(needles)
    return {"declared_freelist_count": declared, "walked_free_pages": len(free),
            "page_size": page_size,
            "needles_only_in_freed_pages": only_free,
            "needles_only_in_allocated_pages": only_allocated,
            "needles_in_both_freed_and_allocated": mixed,
            "needles_absent": absent,
            "checked": len(needles), "sample": detail}


def sqlite_pragmas(db_path: str) -> dict:
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    try:
        return {
            "secure_delete": cur.execute("PRAGMA secure_delete").fetchone()[0],
            "freelist_count_pages": cur.execute("PRAGMA freelist_count").fetchone()[0],
            "page_count": cur.execute("PRAGMA page_count").fetchone()[0],
            "page_size": cur.execute("PRAGMA page_size").fetchone()[0],
        }
    finally:
        con.close()


# --------------------------------------------------------------------------
# HNSW index-file forensics
# --------------------------------------------------------------------------

def index_layout(seg: str, dim: int) -> dict:
    """hnswlib slot layout: [links][vector float32 x dim][label uint64]."""
    data = os.path.join(seg, "data_level0.bin")
    size = os.path.getsize(data)
    capacity = os.path.getsize(os.path.join(seg, "length.bin")) // 4
    stride = size // capacity if capacity else 0
    return {"index_bytes": size, "capacity_slots": capacity, "stride_bytes": stride,
            "vector_offset": stride - 8 - dim * 4, "label_offset": stride - 8,
            "link_bytes_per_slot": stride - 8 - dim * 4}


def read_slots(seg: str, dim: int, layout: dict) -> list:
    with open(os.path.join(seg, "data_level0.bin"), "rb") as fh:
        blob = fh.read()
    stride, voff, loff = layout["stride_bytes"], layout["vector_offset"], layout["label_offset"]
    slots = []
    for i in range(layout["capacity_slots"]):
        base = i * stride
        raw = blob[base + voff: base + voff + dim * 4]
        if len(raw) < dim * 4:
            break
        slots.append({"slot": i, "raw": raw,
                      "label": struct.unpack_from("<Q", blob, base + loff)[0]})
    return slots


def sha256(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def nonzero_fraction(path: str) -> float:
    arr = np.frombuffer(open(path, "rb").read(), dtype=np.uint8)
    return round(float((arr != 0).sum()) / max(len(arr), 1), 4)


def erased_still_in_index(seg: str, dim: int, truth32: dict, erased_ids: list) -> dict:
    layout = index_layout(seg, dim)
    if layout["stride_bytes"] <= 0:
        return {"error": "no slots", "layout": layout}
    slots = read_slots(seg, dim, layout)
    present = {s["raw"] for s in slots}
    found = [pid for pid in erased_ids if truth32[pid].tobytes() in present]
    return {"layout": layout,
            "slots_holding_a_vector": sum(1 for s in slots if any(s["raw"])),
            "erased_found_bitwise_identical": len(found),
            "erased_total": len(erased_ids),
            "index_nonzero_fraction": nonzero_fraction(
                os.path.join(seg, "data_level0.bin"))}


def id_map_state(seg: str, erased_ids: list) -> dict:
    """The segment keeps its own id <-> index-label map. Does it still name the
    erased records? If it does, a ghost vector can be tied back to a record id.
    """
    import pickle
    p = os.path.join(seg, "index_metadata.pickle")
    if not os.path.exists(p):
        return {"present": False}
    with open(p, "rb") as fh:
        obj = pickle.load(fh)
    id_to_label = obj.get("id_to_label", {}) if isinstance(obj, dict) else {}
    return {
        "present": True,
        "file_bytes": os.path.getsize(p),
        "id_to_label_entries": len(id_to_label),
        "label_to_id_entries": len(obj.get("label_to_id", {})) if isinstance(obj, dict) else None,
        "total_elements_added": obj.get("total_elements_added") if isinstance(obj, dict) else None,
        "erased_ids_still_mapped": sum(1 for e in erased_ids if e in id_to_label),
        "erased_total": len(erased_ids),
    }


def cosine(a, b) -> float:
    a = np.asarray(a, dtype=np.float64)
    b = np.asarray(b, dtype=np.float64)
    d = np.linalg.norm(a) * np.linalg.norm(b)
    return float(np.dot(a, b) / d) if d else 0.0


# --------------------------------------------------------------------------
# the run
# --------------------------------------------------------------------------

def main():
    patients = build_patients()
    by_pid = {p["pid"]: p for p in patients}
    rng = random.Random(SEED + 1)
    erased_idx = sorted(rng.sample(range(N_PATIENTS), N_ERASED))
    erased_ids = [patients[i]["pid"] for i in erased_idx]

    R["config"] = {
        "seed": SEED,
        "chromadb": chromadb.__version__,
        "python": sys.version.split()[0],
        "n_patients": N_PATIENTS,
        "n_erased": N_ERASED,
        "n_follow_on_writes": N_FOLLOW_ON_WRITES,
        "embedding_function": "chroma default (ONNX all-MiniLM-L6-v2, 384-dim)",
        "collection_settings": "all Chroma defaults (hnsw space l2, sync_threshold 1000)",
        "erased_ids_first_5": erased_ids[:5],
        "erased_names_first_5": [by_pid[p]["name"] for p in erased_ids[:5]],
    }

    store = os.path.join(tempfile.gettempdir(),
                         f"erasure_2026_08_store{'_' + _TAG if _TAG else ''}")
    for suffix in ("", "_writes", "_vacuum", "_dropcol"):
        p = store + suffix
        if os.path.exists(p):
            shutil.rmtree(p, ignore_errors=True)
    R["store_path"] = store

    # ---- A: build the knowledge base ------------------------------------
    client = chromadb.PersistentClient(path=store)
    col = client.create_collection("clinic_notes")
    B = 500
    for s in range(0, N_PATIENTS, B):
        chunk = patients[s:s + B]
        col.add(ids=[p["pid"] for p in chunk],
                documents=[p["note"] for p in chunk],
                metadatas=[{"patient": p["name"]} for p in chunk])
    R["A_records_loaded"] = col.count()
    R["A_files"] = file_inventory(store)

    got = col.get(include=["embeddings"])
    truth32 = {i: np.asarray(v, dtype=np.float32)
               for i, v in zip(got["ids"], got["embeddings"])}
    dim = len(next(iter(truth32.values())))
    R["A_dim"] = dim
    seg0 = segment_dir(store)
    R["A_index_persisted"] = {
        "segment": os.path.basename(seg0) if seg0 else None,
        "nonzero_fraction": nonzero_fraction(os.path.join(seg0, "data_level0.bin")) if seg0 else None,
        "layout": index_layout(seg0, dim) if seg0 else None,
    }

    # ---- B: the erasure requests ----------------------------------------
    idx_path = os.path.join(seg0, "data_level0.bin")
    hash_before = sha256(idx_path)
    col.delete(ids=erased_ids)
    R["B_count_after_delete"] = col.count()
    R["B_files"] = file_inventory(store)
    hash_after = sha256(idx_path)
    R["B_index_file_unchanged"] = {
        "sha256_before_delete": hash_before,
        "sha256_after_delete": hash_after,
        "byte_identical": hash_before == hash_after,
    }

    # ---- C: what the application sees -----------------------------------
    victim = by_pid[erased_ids[0]]
    q = col.query(query_texts=[victim["note"]], n_results=3)
    R["C_api_view"] = {
        "get_by_id_returns": col.get(ids=erased_ids)["ids"],
        "full_scan_returns": len(col.get()["ids"]),
        "query_with_victims_own_note": {
            "victim_id": victim["pid"],
            "returned_ids": q["ids"][0],
            "victim_present": victim["pid"] in q["ids"][0],
        },
    }
    del col, client
    close_chroma()

    client = chromadb.PersistentClient(path=store)
    col = client.get_collection("clinic_notes")
    R["C_after_restart"] = {"count": col.count(),
                            "get_by_id_returns": col.get(ids=erased_ids)["ids"]}
    del col, client
    close_chroma()

    # ---- D: storage-layer forensics -------------------------------------
    db = os.path.join(store, "chroma.sqlite3")
    R["D_sqlite_state"] = sqlite_state(db)
    R["D_sqlite_pragmas"] = sqlite_pragmas(db)
    R["D_wal_recovery"] = wal_recover(db, erased_ids)

    # identity needles. Names are unique in this fixture, but email and Medicare
    # are unique by construction, so they cannot be confused with another patient.
    needles = {}
    for pid in erased_ids:
        p = by_pid[pid]
        needles[f"{pid}:name"] = p["name"].encode()
        needles[f"{pid}:medicare"] = p["medicare"].encode()
        needles[f"{pid}:email"] = p["email"].encode()
    hits = byte_hits(store, needles)
    R["D_byte_hits_sample"] = dict(list(hits.items())[:6])
    R["D_byte_hit_counts"] = {
        "names_still_on_disk": sum(1 for pid in erased_ids if f"{pid}:name" in hits),
        "medicare_still_on_disk": sum(1 for pid in erased_ids if f"{pid}:medicare" in hits),
        "emails_still_on_disk": sum(1 for pid in erased_ids if f"{pid}:email" in hits),
        "of_total": N_ERASED,
    }

    # where does that residue live - a live table, or freed pages?
    # two independent tests: an exhaustive all-columns SELECT scan, and a walk
    # of the SQLite freelist to see which pages the bytes actually sit in.
    live_reachable = 0
    live_detail = {}
    for n, pid in enumerate(erased_ids):
        lh = live_sql_hits(db, by_pid[pid]["email"])
        if lh:
            live_reachable += 1
        if n < 3:
            live_detail[pid] = lh
    email_needles = {k: v for k, v in needles.items() if k.endswith(":email")}
    R["D_residue_location"] = {
        "erased_records_reachable_by_any_live_sql_column": live_reachable,
        "of_total": N_ERASED,
        "columns_scanned_per_record": "every column of every table",
        "sample_live_queries": live_detail,
        "freelist_walk": residue_in_free_pages(db, email_needles),
    }

    seg = segment_dir(store)
    R["D_index_forensics"] = erased_still_in_index(seg, dim, truth32, erased_ids)
    R["D_id_map"] = id_map_state(seg, erased_ids)

    layout = index_layout(seg, dim)
    slots = read_slots(seg, dim, layout)
    live_slots = [s for s in slots if any(s["raw"])]
    raw_to_pid = {truth32[pid].tobytes(): pid for pid in truth32}
    recovered = [(s, raw_to_pid.get(s["raw"])) for s in live_slots]
    R["D_blind_recovery"] = {
        "slots_scanned": len(slots),
        "slots_holding_a_vector": len(live_slots),
        "vectors_matched_to_a_patient": sum(1 for _s, pid in recovered if pid),
        "of_which_erased": sum(1 for _s, pid in recovered if pid in set(erased_ids)),
        "live_records_in_collection": N_PATIENTS - N_ERASED,
    }
    sample_pid = erased_ids[0]
    sample_slot = next((s for s, pid in recovered if pid == sample_pid), None)
    R["D_ghost_sample"] = {
        "patient_id": sample_pid,
        "patient_name": by_pid[sample_pid]["name"],
        "slot": sample_slot["slot"] if sample_slot else None,
        "cosine_to_original": round(
            cosine(np.frombuffer(sample_slot["raw"], dtype=np.float32),
                   truth32[sample_pid]), 12) if sample_slot else None,
        "first_6_floats": np.frombuffer(sample_slot["raw"], dtype=np.float32)[:6].tolist()
        if sample_slot else None,
    }

    # ---- E: re-identification from the recovered vectors -----------------
    ef = embedding_functions.ONNXMiniLM_L6_V2()
    pool = np.stack([np.frombuffer(s["raw"], dtype=np.float32) for s in live_slots]).astype(np.float64)
    pool /= np.linalg.norm(pool, axis=1, keepdims=True)
    slot_index = {s["slot"]: k for k, s in enumerate(live_slots)}
    ghost_slot_of = {pid: s["slot"] for s, pid in recovered if pid in set(erased_ids)}

    # CONTROL: the same probe against 100 patients who were never deleted.
    # Their notes are still live in the store, so whatever they score is plain
    # retrieval, not a consequence of erasure. The gap between the two rows is
    # what the ghost result actually adds.
    live_pids = [s_pid for _s, s_pid in recovered
                 if s_pid and s_pid not in set(erased_ids)][:N_ERASED]
    slot_of_pid = {s_pid: s["slot"] for s, s_pid in recovered if s_pid}

    reid = {}
    for mode in ("name_only", "name_and_dob", "control_live_records_name_only"):
        texts, targets = [], []
        cohort = live_pids if mode.startswith("control") else erased_ids
        for pid in cohort:
            slot = ghost_slot_of.get(pid) if not mode.startswith("control") \
                else slot_of_pid.get(pid)
            if slot is None:
                continue
            p = by_pid[pid]
            texts.append(f"{p['name']}, born {p['dob']}"
                         if mode == "name_and_dob" else p["name"])
            targets.append(slot_index[slot])
        if not texts:
            reid[mode] = {"n": 0}
            continue
        pv = np.asarray(ef(texts), dtype=np.float64)
        pv /= np.linalg.norm(pv, axis=1, keepdims=True)
        sims = pv @ pool.T
        ranks = []
        for k, tgt in enumerate(targets):
            order = np.argsort(-sims[k])
            ranks.append(int(np.where(order == tgt)[0][0]) + 1)
        reid[mode] = {
            "n": len(ranks),
            "candidate_pool": len(live_slots),
            "rank1": sum(1 for r in ranks if r == 1),
            "rank5": sum(1 for r in ranks if r <= 5),
            "rank10": sum(1 for r in ranks if r <= 10),
            "median_rank": int(np.median(ranks)),
        }
    R["E_reidentification"] = reid

    # ---- F: mitigations --------------------------------------------------
    mit = {}

    # F1 - keep using the store; does normal write traffic overwrite the ghosts?
    w = store + "_writes"
    shutil.copytree(store, w)
    cw = chromadb.PersistentClient(path=w)
    colw = cw.get_collection("clinic_notes")
    for s in range(0, N_FOLLOW_ON_WRITES, B):
        n = min(B, N_FOLLOW_ON_WRITES - s)
        colw.add(ids=[f"NEW-{s + k:05d}" for k in range(n)],
                 documents=[f"New patient record {s + k}, routine check-up, nothing noted."
                            for k in range(n)])
    count_w = colw.count()
    del colw, cw
    close_chroma()
    wseg = segment_dir(w)
    mit["F1_continued_writes"] = {
        "writes_added": N_FOLLOW_ON_WRITES,
        "collection_count": count_w,
        "index_bytes": os.path.getsize(os.path.join(wseg, "data_level0.bin")),
        **erased_still_in_index(wseg, dim, truth32, erased_ids),
        "emails_still_on_disk": sum(
            1 for pid in erased_ids if f"{pid}:email" in byte_hits(w, needles)),
    }

    # F2 - the documented cleanup path
    v = store + "_vacuum"
    shutil.copytree(store, v)
    chroma_exe = os.path.join(os.path.dirname(sys.executable), "chroma.exe")
    if not os.path.exists(chroma_exe):
        chroma_exe = os.path.join(os.path.dirname(sys.executable), "chroma")
    proc = subprocess.run([chroma_exe, "vacuum", "--path", v, "--force"],
                          capture_output=True, text=True)
    f2 = {"command": "chroma vacuum --path <store> --force",
          "returncode": proc.returncode,
          "stdout": proc.stdout.strip()[-500:], "stderr": proc.stderr.strip()[-500:]}
    if os.path.exists(os.path.join(v, "chroma.sqlite3")):
        f2["sqlite_state"] = sqlite_state(os.path.join(v, "chroma.sqlite3"))
        f2["wal_recovery"] = wal_recover(os.path.join(v, "chroma.sqlite3"), erased_ids)
        vhits = byte_hits(v, needles)
        f2["emails_still_on_disk"] = sum(1 for pid in erased_ids if f"{pid}:email" in vhits)
        f2["medicare_still_on_disk"] = sum(1 for pid in erased_ids if f"{pid}:medicare" in vhits)
        # names measured AFTER the vacuum too, so the before/after claim is symmetric
        f2["names_still_on_disk"] = sum(1 for pid in erased_ids if f"{pid}:name" in vhits)
        f2["names_before_vacuum"] = R["D_byte_hit_counts"]["names_still_on_disk"]
        f2["pragmas"] = sqlite_pragmas(os.path.join(v, "chroma.sqlite3"))
        f2["erased_reachable_by_live_sql"] = sum(
            1 for pid in erased_ids
            if any(isinstance(x, int) and x > 0
                   for x in live_sql_hits(os.path.join(v, "chroma.sqlite3"),
                                          by_pid[pid]["email"]).values()))
        vseg = segment_dir(v)
        if vseg:
            f2.update(erased_still_in_index(vseg, dim, truth32, erased_ids))
        f2["files"] = file_inventory(v)
    mit["F2_vacuum"] = f2

    # F3 - drop the whole collection
    d = store + "_dropcol"
    shutil.copytree(store, d)
    cd = chromadb.PersistentClient(path=d)
    cd.delete_collection("clinic_notes")
    del cd
    close_chroma()
    dhits = byte_hits(d, needles)
    mit["F3_delete_collection"] = {
        "files": file_inventory(d),
        "segment_dir_remaining": segment_dir(d) is not None,
        "emails_still_on_disk": sum(1 for pid in erased_ids if f"{pid}:email" in dhits),
        "medicare_still_on_disk": sum(1 for pid in erased_ids if f"{pid}:medicare" in dhits),
        "of_total": N_ERASED,
    }
    dseg = segment_dir(d)
    if dseg:
        mit["F3_delete_collection"].update(
            {"index_" + k: v for k, v in
             erased_still_in_index(dseg, dim, truth32, erased_ids).items()})
    R["F_mitigations"] = mit

    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(R, fh, indent=2, default=str)

    # ---- console summary -------------------------------------------------
    p = print
    p("=" * 74)
    p(f"chromadb {chromadb.__version__} | {N_PATIENTS} records | "
      f"{N_ERASED} erasure requests | seed {SEED}")
    p("=" * 74)
    p(f"count after delete                   : {R['B_count_after_delete']}")
    p(f"get() on erased ids                  : {R['C_api_view']['get_by_id_returns']}")
    p(f"after restart, get() on erased ids    : {R['C_after_restart']['get_by_id_returns']}")
    p(f"index file byte-identical after delete: "
      f"{R['B_index_file_unchanged']['byte_identical']} "
      f"(sha256 {R['B_index_file_unchanged']['sha256_after_delete'][:16]}...)")
    p(f"erased emails still in chroma.sqlite3 : "
      f"{R['D_byte_hit_counts']['emails_still_on_disk']}/{N_ERASED}")
    p(f"erased Medicare nos still on disk     : "
      f"{R['D_byte_hit_counts']['medicare_still_on_disk']}/{N_ERASED}")
    fl = R['D_residue_location']['freelist_walk']
    p(f"  reachable by ANY live SQL column    : "
      f"{R['D_residue_location']['erased_records_reachable_by_any_live_sql_column']}"
      f"/{N_ERASED}")
    p(f"  freelist walk (disjoint)            : "
      f"only-freed {fl['needles_only_in_freed_pages']}, "
      f"only-allocated {fl['needles_only_in_allocated_pages']}, "
      f"both {fl['needles_in_both_freed_and_allocated']}, "
      f"absent {fl['needles_absent']} of {fl['checked']} "
      f"({fl['walked_free_pages']} free pages x {fl['page_size']}B)")
    p(f"WAL: surviving ADD rows for erased    : "
      f"{R['D_wal_recovery'].get('records_with_surviving_add_row')}/{N_ERASED} "
      f"(vector {R['D_wal_recovery'].get('records_with_vector_in_wal')}, "
      f"doc text {R['D_wal_recovery'].get('records_with_document_text_in_wal')}) "
      f"- auto-purge is on by default in this version")
    p(f"erased vectors bitwise-intact in index: "
      f"{R['D_index_forensics'].get('erased_found_bitwise_identical')}/{N_ERASED}")
    p(f"erased ids still in the id->label map : "
      f"{R['D_id_map'].get('erased_ids_still_mapped')}/{N_ERASED} "
      f"({R['D_id_map'].get('id_to_label_entries')} entries for "
      f"{N_PATIENTS - N_ERASED} live records)")
    p(f"vectors recovered blind from index    : "
      f"{R['D_blind_recovery']['slots_holding_a_vector']} "
      f"(live records {N_PATIENTS - N_ERASED}, of which erased "
      f"{R['D_blind_recovery']['of_which_erased']})")
    for mode, dct in reid.items():
        if dct.get("n"):
            p(f"re-id [{mode:31s}]: rank-1 {dct['rank1']}/{dct['n']}  "
              f"rank-5 {dct['rank5']}/{dct['n']}  pool {dct['candidate_pool']}")
    f1 = mit["F1_continued_writes"]
    p(f"F1 after {N_FOLLOW_ON_WRITES} more writes         : "
      f"{f1.get('erased_found_bitwise_identical')}/{N_ERASED} ghosts intact, "
      f"emails on disk {f1.get('emails_still_on_disk')}/{N_ERASED}")
    p(f"F2 vacuum rc={mit['F2_vacuum']['returncode']}                        : "
      f"{mit['F2_vacuum'].get('erased_found_bitwise_identical')}/{N_ERASED} ghosts intact, "
      f"emails {mit['F2_vacuum'].get('emails_still_on_disk')}/{N_ERASED}, "
      f"medicare {mit['F2_vacuum'].get('medicare_still_on_disk')}/{N_ERASED}, "
      f"names {mit['F2_vacuum'].get('names_before_vacuum')}->"
      f"{mit['F2_vacuum'].get('names_still_on_disk')}")
    p(f"F3 delete_collection                  : "
      f"emails on disk {mit['F3_delete_collection']['emails_still_on_disk']}/{N_ERASED}, "
      f"ghosts in index "
      f"{mit['F3_delete_collection'].get('index_erased_found_bitwise_identical')}/{N_ERASED}, "
      f"segment dir left: {mit['F3_delete_collection']['segment_dir_remaining']}")
    p(f"\nraw JSON -> {OUT_JSON}")


if __name__ == "__main__":
    main()
