# Local activation storage

SQLite stores only the activation cache: product ID, opaque server license and
device IDs, activation ID, status, and update timestamp. The schema is added
with `CREATE TABLE IF NOT EXISTS` as a forward-compatible migration step.
Tokens, passwords, raw hardware values, and offline authorization claims are
not stored. Local rows are cache and diagnostics only and cannot authorize
launch.
