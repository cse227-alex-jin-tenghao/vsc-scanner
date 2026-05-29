-- Atomically claim one group of 100 extensions for a node to scan.
-- Parameters:
--   $1 :: text  — node identifier (hostname / pod name), stored on the row
--                  so a stuck claim can be traced back to the killer.
--
-- Returns one row {group_idx, last_completed_idx} or zero rows if the
-- whole table is drained.
--
-- A group is claimable if it is:
--   (a) unclaimed, OR
--   (b) claimed but the claim is older than 1 hour (assume the holder died).
-- Completed groups are excluded by the partial index on manager.
--
-- FOR UPDATE SKIP LOCKED lets many nodes call claim() in parallel without
-- blocking on each other — each picks the next free row.

UPDATE manager
SET status = 'claimed',
    claimed_at = now(),
    claimed_by = $1,
    attempts = attempts + 1
WHERE group_idx = (
    SELECT group_idx FROM manager
    WHERE status = 'unclaimed'
       OR (status = 'claimed' AND claimed_at < now() - interval '1 hour')
    ORDER BY group_idx
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING
    group_idx,
    -- Highest idx within this group already populated, so the node can
    -- resume after a partial failure without re-scanning finished rows.
    (SELECT COALESCE(MAX(idx), group_idx * 100 - 1)
       FROM main
      WHERE idx >= group_idx * 100
        AND idx <  group_idx * 100 + 100
        AND completed_at IS NOT NULL) AS last_completed_idx;
