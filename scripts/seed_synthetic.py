"""Seed a local Chroma store with SYNTHETIC (fake) sensitive records for testing.

Run after:  pip install -e ".[chroma,dev]"

    python scripts/seed_synthetic.py                 # 100 fake records -> ./sample_store
    python scripts/seed_synthetic.py 250 ./mystore   # custom count + path

⚠️  FAKE DATA ONLY — never seed real PII.

Why this exists: a scanner needs something to scan. This builds a *known-answer*
fixture — every record embeds a fixed set of PII inside free-text clinical notes
(the real-world anti-pattern), so on Day 4 we can measure detection recall against
a ground truth we control.
"""
import random
import sys

from faker import Faker

fake = Faker("en_AU")  # Australian-flavoured fake data
CLINIC = "Brightsmile Dental (fictional)"

# Each record contains exactly these PII types — that's our ground truth.
PII_PER_RECORD = ("name", "email", "phone", "dob", "medicare", "address")


def fake_medicare() -> str:
    """A plausible-looking but FAKE Medicare-style number. Not a real card number."""
    return f"{random.randint(2, 6)}{random.randint(0, 9_999_999):07d} {random.randint(1, 9)} {random.randint(1, 9)}"


def make_record(i: int) -> dict:
    name = fake.name()
    email = fake.email()
    phone = fake.phone_number()
    dob = fake.date_of_birth(minimum_age=18, maximum_age=90).strftime("%d/%m/%Y")
    medicare = fake_medicare()
    address = fake.address().replace("\n", ", ")
    complaint = random.choice([
        "tooth pain, lower left molar",
        "follow-up after root canal",
        "anxiety about extraction; requested sedation",
        "bleeding gums and sensitivity",
        "requesting records be transferred to a new dentist",
    ])
    # PII deliberately embedded in free text — exactly what ends up in a vector DB.
    note = (
        f"Patient {name} (DOB {dob}, Medicare {medicare}) called re: {complaint}. "
        f"Best contact {phone} or {email}. Address on file: {address}."
    )
    return {
        "id": f"rec-{i:04d}",
        "text": note,
        "metadata": {"record_id": f"rec-{i:04d}", "clinic": CLINIC, "type": "clinical_note"},
    }


def main(n: int, path: str) -> None:
    import chromadb

    print(f"Generating {n} FAKE clinic records -> embedding into Chroma at '{path}' …")
    print("(first run downloads a small embedding model; one-time)\n")

    records = [make_record(i) for i in range(n)]
    client = chromadb.PersistentClient(path=path)
    try:
        client.delete_collection("clinic_notes")  # fresh each run
    except Exception:
        pass
    col = client.create_collection("clinic_notes")
    col.add(
        ids=[r["id"] for r in records],
        documents=[r["text"] for r in records],
        metadatas=[r["metadata"] for r in records],
    )

    expected = n * len(PII_PER_RECORD)
    print(f"✅ Seeded {n} records into collection 'clinic_notes'.")
    print(f"   Ground truth: each record has {len(PII_PER_RECORD)} PII items {PII_PER_RECORD}.")
    print(f"   → expected sensitive entities = {n} x {len(PII_PER_RECORD)} = {expected} (Day-4 recall target).")
    print(f"\nExample note:\n   {records[0]['text']}")
    print("\nNext: build the Chroma connector (Day 3) to read these back out.")


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    path = sys.argv[2] if len(sys.argv) > 2 else "./sample_store"
    main(n, path)
