from django.contrib.auth.hashers import PBKDF2PasswordHasher


class StablePBKDF2PasswordHasher(PBKDF2PasswordHasher):
    """PBKDF2 with a fixed iteration count that matches the hashes stored in db.sqlite3.

    Django changes the default iteration count between releases. When the runtime Django
    version (e.g. 5.0.x on Vercel) differs from the one that created the hashes, every
    login "upgrades" the hash. On serverless hosts each instance has its own SQLite copy,
    so the upgraded hash lives on one instance only; other instances then see a different
    password hash and Django invalidates the session -> the admin is logged out.
    Pinning the count means existing hashes are never rewritten on login.
    """
    iterations = 1_500_000

