-- Fixes the epoch of this database: 16 random bytes as 32 lowercase hex characters, chosen once.
-- Runs once, as the owner of the database, like 0001_init.sql.
--
-- Every Policy Bundle carries the epoch. Versions count from 1 per database, so a database that was wiped
-- while the signing key beside it was kept issues version 1 again: Shield compares versions only within
-- one epoch and accepts a new epoch instead of refusing its bundles as replays of older versions.

-- Exactly one row: the primary key admits a single value of `id`, and the check admits only that one.
CREATE TABLE database_epoch (
  id boolean PRIMARY KEY DEFAULT true CHECK (id),
  epoch text NOT NULL CHECK (epoch ~ '^[0-9a-f]{32}$'),
  created_at timestamptz NOT NULL DEFAULT now()
);

-- PostgreSQL has no built-in for random bytes (gen_random_bytes is pgcrypto). gen_random_uuid() draws from
-- the server's strong random source: two of them hold 244 random bits, hashed down to 128.
INSERT INTO database_epoch (epoch)
VALUES (left(encode(sha256(convert_to(gen_random_uuid()::text || gen_random_uuid()::text, 'UTF8')), 'hex'), 32));

-- Not tenant data: no row-level security. The request role reads it and can change nothing.
GRANT SELECT ON database_epoch TO ar_app;
