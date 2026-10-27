// Host quarantine: take a host that has stopped answering with a paywall out of every count
// and list, and put it back once it answers again (2026-10-27).
//
// Motivating case: market.datapackvibe.com, ~70k Bazaar rows on one hostname. Its Cloudflare
// tunnel went dark 2026-10-18 (530, "error code: 1033"), came back by 10-25, and was dark again
// 10-27 (x402-foundation/x402#3844). One flapping host was a third of the index.
//
// Once per health run, before the sweep, each tracked host gets a host-level probe: its apex
// plus up to SAMPLE rows chosen at random. A probe set FAILS when no response is a 402 or 2xx
// (network errors and timeouts count as failures). It PASSES when at least one response is 402.
//   new host, fails          → watch, fail_streak 1
//   watch, fails ENTER times → quarantined
//   watch, any 402/2xx       → dropped from the table
//   quarantined, passes EXIT runs in a row → released (row deleted); any non-pass resets
// Quarantined rows are skipped by the sweep (getServices), so this probe is the only thing
// still watching them.
import { probeEndpoint } from '../services/probe-endpoint.js'
import { ACTIVE, QUARANTINE_ENABLED } from '../services/visibility.js'

export const SAMPLE = 5
export const ENTER = 3
export const EXIT = 3
export const MIN_GAP_MINUTES = 45
const HOST_CONCURRENCY = 16
const MIN_ROWS = 5

async function defaultProbe(url, method, body) {
  const r = await probeEndpoint(url, { method: method || 'GET', body: body || '{}', followRedirects: true })
  return r.errorMessage ? null : r.httpStatus
}

const ok = s => s === 402 || (s >= 200 && s < 300)

/**
 * Discover failing hosts and advance every tracked host's state.
 * @param {object} database
 * @param {{ probe?: (url: string, method?: string, body?: string) => Promise<number|null> }} [opts]
 */
export async function evaluateQuarantine(database, { probe = defaultProbe, minGapMinutes = MIN_GAP_MINUTES } = {}) {
  if (!QUARANTINE_ENABLED) return { evaluated: 0 }

  // A host's streak advances at most once per MIN_GAP_MINUTES. Runs start at every boot, and on
  // 2026-10-27 three deploys in 25 minutes walked 102 hosts through "3 failing runs" — the rule
  // means three sweeps, roughly three hours of evidence.
  const tracked = database.prepare(
    `SELECT * FROM quarantined_hosts WHERE last_probe_at IS NULL OR last_probe_at <= datetime('now', ?)`
  ).all(`-${minGapMinutes} minutes`)
  const recentlyProbed = database.prepare(
    `SELECT hostname FROM quarantined_hosts WHERE last_probe_at > datetime('now', ?)`
  ).all(`-${minGapMinutes} minutes`).map(r => r.hostname)
  const known = new Set([...tracked.map(t => t.hostname), ...recentlyProbed])
  // A host whose rows the sweep has driven down and none of which answers healthy. Uses the
  // sweep's own verdicts, so a host only becomes a candidate after the sweep has seen it fail.
  const candidates = database.prepare(`
    SELECT hostname FROM services WHERE ${ACTIVE} AND hostname IS NOT NULL
    GROUP BY hostname
    HAVING COUNT(*) >= ${MIN_ROWS} AND SUM(health_status = 'healthy') = 0 AND SUM(health_status = 'down') * 2 >= COUNT(*)
  `).all().map(r => r.hostname).filter(h => !known.has(h))

  const sampleRows = database.prepare(
    `SELECT url, http_method, probe_body FROM services WHERE hostname = ? AND ${ACTIVE} ORDER BY random() LIMIT ${SAMPLE}`
  )
  const upsert = database.prepare(`
    INSERT INTO quarantined_hosts (hostname, state, fail_streak, pass_streak, entered_at, last_probe_at, last_http_status, reason)
    VALUES (@hostname, @state, @fail_streak, @pass_streak, @entered_at, datetime('now'), @last_http_status, @reason)
    ON CONFLICT (hostname) DO UPDATE SET state = excluded.state, fail_streak = excluded.fail_streak,
      pass_streak = excluded.pass_streak, entered_at = excluded.entered_at, last_probe_at = excluded.last_probe_at,
      last_http_status = excluded.last_http_status, reason = COALESCE(quarantined_hosts.reason, excluded.reason)
  `)
  const drop = database.prepare('DELETE FROM quarantined_hosts WHERE hostname = ?')

  const summary = { evaluated: 0, entered: [], released: [], watching: 0, quarantined: 0 }
  const hosts = [...tracked, ...candidates.map(h => ({ hostname: h, state: null, fail_streak: 0, pass_streak: 0, entered_at: null }))]

  // Hosts are independent, so probe up to HOST_CONCURRENCY of them at once: on 2026-10-27 the
  // first run found 386 candidate hosts, and probing them one by one held the sweep ~20 min.
  // A host's own probes stay sequential. State writes are synchronous, so workers never interleave.
  async function evaluateHost(host) {
    const targets = [{ url: `https://${host.hostname}/`, http_method: 'GET', probe_body: null }, ...sampleRows.all(host.hostname)]
    const statuses = []
    for (const t of targets) {
      try { statuses.push(await probe(t.url, t.http_method, t.probe_body)) } catch { statuses.push(null) }
    }
    summary.evaluated++
    const fails = !statuses.some(ok)
    const passes = statuses.includes(402)
    const last = statuses.find(s => s != null) ?? null
    const reason = `no 402/2xx from apex + ${targets.length - 1} rows: ${statuses.join(',')}`

    if (host.state === 'quarantined') {
      const streak = passes ? host.pass_streak + 1 : 0
      if (streak >= EXIT) {
        drop.run(host.hostname)
        summary.released.push(host.hostname)
        console.log(`[quarantine] released ${host.hostname} after ${EXIT} passing runs (${statuses.join(',')})`)
      } else {
        upsert.run({ hostname: host.hostname, state: 'quarantined', fail_streak: passes ? host.fail_streak : host.fail_streak + 1,
          pass_streak: streak, entered_at: host.entered_at, last_http_status: last, reason })
        summary.quarantined++
      }
      return
    }

    if (!fails) {
      if (host.state === 'watch') drop.run(host.hostname)
      return
    }
    const streak = host.fail_streak + 1
    if (streak >= ENTER) {
      upsert.run({ hostname: host.hostname, state: 'quarantined', fail_streak: streak, pass_streak: 0,
        entered_at: new Date().toISOString().replace('T', ' ').slice(0, 19), last_http_status: last, reason })
      summary.entered.push(host.hostname)
      summary.quarantined++
      console.log(`[quarantine] quarantined ${host.hostname} after ${ENTER} failing runs (${statuses.join(',')})`)
    } else {
      upsert.run({ hostname: host.hostname, state: 'watch', fail_streak: streak, pass_streak: 0, entered_at: null, last_http_status: last, reason })
      summary.watching++
    }
  }
  let next = 0
  await Promise.all(Array.from({ length: Math.min(HOST_CONCURRENCY, hosts.length) }, async () => {
    while (next < hosts.length) await evaluateHost(hosts[next++])
  }))
  if (summary.evaluated > 0) console.log(`[quarantine] evaluated ${summary.evaluated} hosts: quarantined=${summary.quarantined} watching=${summary.watching} entered=${summary.entered.length} released=${summary.released.length}`)
  return summary
}
