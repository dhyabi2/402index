// Which services count. One definition, imported by every count, list and feed (2026-10-27).
//
// LISTED = active (not pending/rejected/retired), not provider-deleted, and not on a
// quarantined host. A host is quarantined when it has stopped answering with a paywall
// (src/health/quarantine.js); its rows keep their /service/:id page but leave every count,
// default list, llms.txt, feed.xml and digest. Before this module each route carried its own
// copy of the active filter, which is how counts drift apart.
//
// QUARANTINE_ENABLED=false restores the old counts without a schema change.

export const QUARANTINE_ENABLED = process.env.QUARANTINE_ENABLED !== 'false'

export const ACTIVE = "(status = 'active' OR status IS NULL) AND (provider_deleted = 0 OR provider_deleted IS NULL)"

export const NOT_QUARANTINED = QUARANTINE_ENABLED
  ? "(hostname IS NULL OR hostname NOT IN (SELECT hostname FROM quarantined_hosts WHERE state = 'quarantined'))"
  : '1'

export const LISTED = `${ACTIVE} AND ${NOT_QUARANTINED}`

export function ensureQuarantineSchema(database) {
  database.exec(`
    CREATE TABLE IF NOT EXISTS quarantined_hosts (
      hostname TEXT PRIMARY KEY,
      -- watch: failing, not yet excluded. quarantined: excluded from counts and lists.
      state TEXT NOT NULL CHECK (state IN ('watch', 'quarantined')),
      fail_streak INTEGER NOT NULL DEFAULT 0,
      pass_streak INTEGER NOT NULL DEFAULT 0,
      entered_at TEXT,
      last_probe_at TEXT,
      last_http_status INTEGER,
      reason TEXT,
      seeded INTEGER NOT NULL DEFAULT 0
    )
  `)
}

/** Active rows hidden by quarantine. 0 when the flag is off. */
export function countQuarantined(database) {
  if (!QUARANTINE_ENABLED) return 0
  return database.prepare(
    `SELECT COUNT(*) AS c FROM services WHERE ${ACTIVE} AND hostname IN (SELECT hostname FROM quarantined_hosts WHERE state = 'quarantined')`
  ).get().c
}

export function isHostQuarantined(database, hostname) {
  if (!QUARANTINE_ENABLED || !hostname) return null
  return database.prepare("SELECT hostname, entered_at, reason, last_http_status FROM quarantined_hosts WHERE hostname = ? AND state = 'quarantined'").get(hostname) || null
}
