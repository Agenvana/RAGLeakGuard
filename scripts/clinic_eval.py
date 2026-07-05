"""End-to-end clinic-scan evaluation with ground truth.

Seeds a synthetic AU dental-clinic Chroma store (seeded Faker → reproducible),
reads it back through the real connector, and measures per-PII-type coverage:
each record contains exactly 6 known PII items (name, email, phone, dob,
medicare, address) at known positions, so we can say which ones a scan caught
and which stayed invisible — default config vs --locale au.

    python scripts/clinic_eval.py                    # 100 records -> ./clinic_store
    python scripts/clinic_eval.py 250 /tmp/store     # custom count + path

⚠️  FAKE DATA ONLY. Companion to scripts/benchmark.py (which measures format
variants in isolation); this one measures the whole pipeline on realistic notes.
"""
import random
import sys

from faker import Faker

SEED = 20260704
ACTIONABLE = 0.4  # same actionable-confidence tier as benchmark.py

COMPLAINTS = [
    "tooth pain, lower left molar",
    "follow-up after root canal",
    "anxiety about extraction; requested sedation",
    "bleeding gums and sensitivity",
    "requesting records be transferred to a new dentist",
]


def fake_medicare():
    return f"{random.randint(2, 6)}{random.randint(0, 9_999_999):07d} {random.randint(1, 9)} {random.randint(1, 9)}"


def make_record(fake, i):
    pii = {
        "name": fake.name(),
        "email": fake.email(),
        "phone": fake.phone_number(),
        "dob": fake.date_of_birth(minimum_age=18, maximum_age=90).strftime("%d/%m/%Y"),
        "medicare": fake_medicare(),
        "address": fake.address().replace("\n", ", "),
    }
    note = (
        f"Patient {pii['name']} (DOB {pii['dob']}, Medicare {pii['medicare']}) called re: "
        f"{random.choice(COMPLAINTS)}. Best contact {pii['phone']} or {pii['email']}. "
        f"Address on file: {pii['address']}."
    )
    return {"id": f"rec-{i:04d}", "text": note, "pii": pii}


def main(n, store):
    import chromadb
    from ragleakguard.connectors import read_chroma
    from ragleakguard.detect import detect

    Faker.seed(SEED)
    random.seed(SEED)
    fake = Faker("en_AU")
    records = {r["id"]: r for r in (make_record(fake, i) for i in range(n))}

    client = chromadb.PersistentClient(path=store)
    try:
        client.delete_collection("clinic_notes")
    except Exception:
        pass
    col = client.create_collection("clinic_notes")
    col.add(ids=list(records), documents=[r["text"] for r in records.values()],
            metadatas=[{"record_id": rid} for rid in records])

    items = list(read_chroma(store))  # end-to-end: through the real connector
    print(f"Read back {len(items)} records through the Chroma connector.\n")

    for locale in (None, "au"):
        coverage = {k: [0, 0, 0] for k in ("name", "email", "phone", "dob", "medicare", "address")}
        fully_clean = 0
        missed_items = []
        for it in items:
            rec = records[it["metadata"]["record_id"]]
            text = it["text"]
            findings = detect(text, locale=locale)
            record_missed = []
            for ptype, value in rec["pii"].items():
                start = text.find(value)
                if start < 0:
                    continue
                end = start + len(value)
                hits = [f for f in findings if f["start"] < end and start < f["end"]]
                act = any(f["score"] >= ACTIONABLE for f in hits)
                coverage[ptype][2] += 1
                coverage[ptype][0] += bool(hits)
                coverage[ptype][1] += act
                if not act:
                    record_missed.append((ptype, value))
            if not record_missed:
                fully_clean += 1
            else:
                missed_items.extend((it["metadata"]["record_id"], p, v) for p, v in record_missed)

        total = sum(v[2] for v in coverage.values())
        caught = sum(v[1] for v in coverage.values())
        print(f"## locale={locale or 'default'}")
        for ptype, (a, act, t) in coverage.items():
            print(f"  {ptype:<9} caught {act:>3}/{t} actionable ({100*act/t:.0f}%)  [any-conf {a}/{t}]")
        print(f"  TOTAL     {caught}/{total} PII items caught ({100*caught/total:.1f}%) — "
              f"{total-caught} items invisible")
        print(f"  Records with every PII item caught: {fully_clean}/{len(items)}")
        for rid, p, v in missed_items[:8]:
            print(f"    missed: {rid} {p} = {v!r}")
        print()


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    store = sys.argv[2] if len(sys.argv) > 2 else "./clinic_store"
    main(n, store)
