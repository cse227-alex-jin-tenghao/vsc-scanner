-- Called once per extension as the node finishes scanning it (per-row
-- upsert, not batched at end-of-group). On a stale-claim recovery the
-- next holder skips this idx because completed_at IS NOT NULL.
--
-- Parameters:
--   $1  idx              integer
--   $2  preprocessing    jsonb
--   $3  dep_visibility   jsonb
--   $4  semgrep_output   jsonb
--   $5  retire_output    jsonb
--   $6  osv_output       jsonb
--   $7  gitleaks_output  jsonb
--   $8  errors           jsonb
--   $9  scanner_version  text

UPDATE main
SET preprocessing   = $2,
    dep_visibility  = $3,
    semgrep_output  = $4,
    retire_output   = $5,
    osv_output      = $6,
    gitleaks_output = $7,
    errors          = $8,
    scanner_version = $9,
    completed_at    = now()
WHERE idx = $1;

-- Mark a group done after its 100th row lands. Cheap to call after every
-- row; the WHERE keeps it a no-op until the group is actually full.
-- Parameters:
--   $1  group_idx  integer

UPDATE manager
SET status = 'completed',
    completed_at = now()
WHERE group_idx = $1
  AND status <> 'completed'
  AND (
    SELECT COUNT(*) FROM main
    WHERE idx >= $1 * 100
      AND idx <  $1 * 100 + 100
      AND completed_at IS NOT NULL
  ) = (
    SELECT COUNT(*) FROM main
    WHERE idx >= $1 * 100
      AND idx <  $1 * 100 + 100
  );
