/**
 * Role-aware notifications hook.
 *
 * Uses timestamp-gated backend endpoints so only events that occur after the
 * current browser session starts generate notifications — seeded/historical
 * data never floods the bell.
 *
 *   admin     – new user registrations (last 24 h), any scan completed/failed
 *   app_owner – own app scan completions/failures, high-risk findings
 *   end_user  – apps made public since session start
 *
 * Seen/dismissed IDs are persisted in localStorage.
 */

import { useState, useEffect, useRef, useCallback } from 'react'
import { appsApi, adminApi } from '../lib/api'
import type { UserRole } from '../lib/types'

// ── Notification shape ────────────────────────────────────────────────────────
export type NotifKind =
  | 'new_user'
  | 'scan_complete'
  | 'scan_failed'
  | 'high_risk'
  | 'cpu_alert'
  | 'pending_backlog'
  | 'pqc_ready'
  | 'report_ready'
  | 'own_scan_complete'
  | 'own_scan_failed'
  | 'own_high_risk'
  | 'new_app_public'

export interface Notification {
  id: string
  kind: NotifKind
  title: string
  sub: string
  unread: boolean
  ts: number   // epoch ms – used for sorting
}

const LS_KEY           = 'qs_notif_seen'
const LS_DISMISSED_KEY = 'qs_notif_dismissed'
const SS_SESSION_KEY   = 'qs_session_start'  // sessionStorage — persists across refreshes, not tab closes

function loadSeen(): Set<string> {
  try { return new Set(JSON.parse(localStorage.getItem(LS_KEY) ?? '[]') as string[]) }
  catch { return new Set() }
}
function saveSeen(ids: Set<string>) {
  localStorage.setItem(LS_KEY, JSON.stringify([...ids]))
}

function loadDismissed(): Set<string> {
  try { return new Set(JSON.parse(localStorage.getItem(LS_DISMISSED_KEY) ?? '[]') as string[]) }
  catch { return new Set() }
}
function saveDismissed(ids: Set<string>) {
  localStorage.setItem(LS_DISMISSED_KEY, JSON.stringify([...ids]))
}

// Persist session start in sessionStorage so page refreshes don't reset the cutoff.
// A new tab / closed-and-reopened tab gets a fresh start time.
function getOrCreateSessionStart(): string {
  try {
    const existing = sessionStorage.getItem(SS_SESSION_KEY)
    if (existing) return existing
    const now = new Date().toISOString()
    sessionStorage.setItem(SS_SESSION_KEY, now)
    return now
  } catch {
    return new Date().toISOString()
  }
}

// Safely convert a backend ISO string (with or without tz suffix) to epoch ms.
function isoToMs(iso: string | null | undefined): number {
  if (!iso) return Date.now()
  // Already has tz info (ends with Z or ±HH:MM) — parse as-is
  if (/Z$|[+-]\d{2}:\d{2}$/.test(iso)) return new Date(iso).getTime()
  // No tz info → treat as UTC
  return new Date(iso + 'Z').getTime()
}

// Poll intervals (ms)
const ADMIN_POLL_MS    = 30_000
const OWNER_POLL_MS    = 20_000
const END_USER_POLL_MS = 60_000

// ── Hook ──────────────────────────────────────────────────────────────────────
export function useNotifications(role: UserRole | undefined, userId: string | undefined) {
  const [notifications, setNotifications] = useState<Notification[]>([])
  const seenRef         = useRef<Set<string>>(loadSeen())
  const dismissedRef    = useRef<Set<string>>(loadDismissed())
  // Session start persisted in sessionStorage — survives F5, not tab close
  const sessionStartRef = useRef<string>(getOrCreateSessionStart())

  // Stable merge: skip dismissed IDs and already-present IDs
  const merge = useCallback((incoming: Notification[]) => {
    setNotifications(prev => {
      const existingIds = new Set(prev.map(n => n.id))
      const dismissed   = dismissedRef.current
      const fresh = incoming.filter(n => !existingIds.has(n.id) && !dismissed.has(n.id))
      if (fresh.length === 0) return prev
      return [...fresh, ...prev].slice(0, 50)
    })
  }, [])

  // ── Admin polls ─────────────────────────────────────────────────────────────
  const pollAdmin = useCallback(async () => {
    const seen    = seenRef.current
    const since   = sessionStartRef.current
    const items: Notification[] = []

    try {
      const [users, health, recentScans] = await Promise.all([
        adminApi.users().catch(() => [] as Awaited<ReturnType<typeof adminApi.users>>),
        adminApi.systemHealth().catch(() => null),
        // Use timestamp-gated endpoint — only scans that completed this session
        appsApi.recentCompletions(since).catch(() => [] as Awaited<ReturnType<typeof appsApi.recentCompletions>>),
      ])

      // New users registered in the last 24 h
      const cutoff24h = Date.now() - 24 * 60 * 60 * 1000
      for (const u of users) {
        const ts = isoToMs(u.created_at)
        if (ts > cutoff24h) {
          const id = `new_user_${u.id}`
          items.push({ id, kind: 'new_user', title: 'New user registered', sub: u.email, unread: !seen.has(id), ts })
        }
      }

      // Pending scan backlog
      if (health && health.pending_scans > 5) {
        const id = `pending_backlog_${Math.floor(Date.now() / 60_000)}`
        if (!items.some(i => i.kind === 'pending_backlog'))
          items.push({ id, kind: 'pending_backlog', title: 'Scan queue backlog', sub: `${health.pending_scans} scans pending`, unread: !seen.has(id), ts: Date.now() })
      }

      // Scans completed/failed since session start
      for (const app of recentScans) {
        const ts = isoToMs(app.scanned_at ?? app.submitted_at)
        const name = app.app_name ?? app.package_name

        if (app.scan_status === 'completed') {
          const id = `scan_complete_${app.id}`
          items.push({ id, kind: 'scan_complete', title: 'Scan completed', sub: name, unread: !seen.has(id), ts })
          if (app.risk_level === 'High' || app.risk_level === 'Critical') {
            const id2 = `high_risk_${app.id}`
            items.push({ id: id2, kind: 'high_risk', title: 'High-risk app detected', sub: `${name} · score ${Math.round(app.security_score ?? 0)}`, unread: !seen.has(id2), ts })
          }
        } else if (app.scan_status === 'failed') {
          const id = `scan_failed_${app.id}`
          items.push({ id, kind: 'scan_failed', title: 'Scan failed', sub: name, unread: !seen.has(id), ts })
        }
      }
    } catch { /* ignore */ }

    merge(items)
  }, [merge])

  // ── App-owner polls ─────────────────────────────────────────────────────────
  const pollOwner = useCallback(async () => {
    if (!userId) return
    const seen  = seenRef.current
    const since = sessionStartRef.current
    const items: Notification[] = []
    const ownerId = parseInt(userId, 10)

    try {
      // Only own apps that finished scanning since session start
      const ownApps = await appsApi.recentCompletions(since, ownerId).catch(() => [])

      for (const app of ownApps) {
        const name = app.app_name ?? app.package_name
        const ts   = isoToMs(app.scanned_at ?? app.submitted_at)

        if (app.scan_status === 'completed') {
          const id = `own_complete_${app.id}`
          items.push({ id, kind: 'own_scan_complete', title: 'Your app analysis is done', sub: name, unread: !seen.has(id), ts })

          if ((app.risk_level === 'High' || app.risk_level === 'Critical') && app.security_score != null) {
            const id2 = `own_high_risk_${app.id}`
            items.push({ id: id2, kind: 'own_high_risk', title: 'High risk detected in your app', sub: `${name} · score ${Math.round(app.security_score)}`, unread: !seen.has(id2), ts })
          }
          if ((app.pqc_readiness_score ?? 0) > 50) {
            const id3 = `own_pqc_${app.id}`
            items.push({ id: id3, kind: 'pqc_ready', title: 'App is PQC-ready', sub: name, unread: !seen.has(id3), ts })
          }
        } else if (app.scan_status === 'failed') {
          const id = `own_failed_${app.id}`
          items.push({ id, kind: 'own_scan_failed', title: 'App scan failed', sub: name, unread: !seen.has(id), ts })
        }
      }
    } catch { /* ignore */ }

    merge(items)
  }, [userId, merge])

  // ── End-user polls ──────────────────────────────────────────────────────────
  const pollEndUser = useCallback(async () => {
    const seen  = seenRef.current
    const since = sessionStartRef.current
    const items: Notification[] = []

    try {
      // Only apps that were explicitly made public since session start
      const newPublic = await appsApi.recentPublic(since).catch(() => [])

      for (const app of newPublic) {
        const name = app.app_name ?? app.package_name
        const ts   = isoToMs(app.made_public_at ?? app.submitted_at)
        const score = app.security_score != null ? ` · score ${Math.round(app.security_score)}` : ''

        const id = `eu_new_app_${app.id}`
        items.push({ id, kind: 'new_app_public', title: 'New app analyzed & published', sub: `${name}${score}`, unread: !seen.has(id), ts })

        if (app.risk_level === 'High' || app.risk_level === 'Critical') {
          const id2 = `eu_high_risk_${app.id}`
          items.push({ id: id2, kind: 'high_risk', title: 'High-risk app published', sub: `${name}${score}`, unread: !seen.has(id2), ts })
        }
        if ((app.pqc_readiness_score ?? 0) > 50) {
          const id3 = `eu_pqc_${app.id}`
          items.push({ id: id3, kind: 'pqc_ready', title: 'PQC-ready app published', sub: name, unread: !seen.has(id3), ts })
        }
      }
    } catch { /* ignore */ }

    merge(items)
  }, [merge])

  // ── Start polling based on role ─────────────────────────────────────────────
  useEffect(() => {
    if (!role) return

    const poll        = role === 'admin' ? pollAdmin : role === 'app_owner' ? pollOwner : pollEndUser
    const intervalMs  = role === 'admin' ? ADMIN_POLL_MS : role === 'app_owner' ? OWNER_POLL_MS : END_USER_POLL_MS

    poll()
    const id = setInterval(poll, intervalMs)
    return () => clearInterval(id)
  }, [role, pollAdmin, pollOwner, pollEndUser])

  // ── Public helpers ──────────────────────────────────────────────────────────
  const markRead = useCallback((notifId: string) => {
    seenRef.current.add(notifId)
    saveSeen(seenRef.current)
    setNotifications(prev => prev.map(n => n.id === notifId ? { ...n, unread: false } : n))
  }, [])

  const markAllRead = useCallback(() => {
    setNotifications(prev => {
      prev.forEach(n => seenRef.current.add(n.id))
      saveSeen(seenRef.current)
      return prev.map(n => ({ ...n, unread: false }))
    })
  }, [])

  const dismiss = useCallback((notifId: string) => {
    dismissedRef.current.add(notifId)
    saveDismissed(dismissedRef.current)
    seenRef.current.add(notifId)
    saveSeen(seenRef.current)
    setNotifications(prev => prev.filter(n => n.id !== notifId))
  }, [])

  const dismissAll = useCallback(() => {
    setNotifications(prev => {
      prev.forEach(n => {
        dismissedRef.current.add(n.id)
        seenRef.current.add(n.id)
      })
      saveDismissed(dismissedRef.current)
      saveSeen(seenRef.current)
      return []
    })
  }, [])

  const unreadCount = notifications.filter(n => n.unread).length

  return { notifications, unreadCount, markRead, markAllRead, dismiss, dismissAll }
}
