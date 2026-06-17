"""Seed a local Chroma store with SYNTHETIC (fake) sensitive records for testing.

Run after:  pip install -e ".[chroma,dev]"
⚠️  FAKE DATA ONLY. Never seed real PII into a test store.

TODO (Day 2): use Faker to generate fake patient/client records (names, emails,
phones, fake Medicare numbers, short clinical notes), embed them, and add to Chroma.
This gives us a known-answer fixture to measure detection recall against.
"""

if __name__ == "__main__":
    print("seed_synthetic: TODO — Day 2 (generate fake records + seed Chroma)")
