import React, { useState, useMemo, useEffect } from 'react'
import {
  Search, Check, X, ArrowRight, ListFilter,
} from 'lucide-react'
import {
  Card, CardContent, CardHeader, CardTitle,
} from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Progress } from '../components/ui/progress'
import { appsApi } from '../lib/api'
import type { AppOut } from '../lib/api'
import {
  scoreColor, scoreBarColor, riskVariant,
} from '../lib/utils'
import type { RiskLevel } from '../lib/types'
import { AppDetailSheet } from '../components/AppDetailSheet'

// ── Star icon ─────────────────────────────────────────────────────────────────
const StarFilled = () => (
  <svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor" className="text-amber-400">
    <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" />
  </svg>
)

// ── Unused re-export kept to avoid breaking change ───────────────────────────

// ── Map AppOut to display values ──────────────────────────────────────────────
function appName(a: AppOut) { return a.app_name ?? a.package_name }
function appScore(a: AppOut) { return Math.round(a.security_score ?? 0) }
function appRisk(a: AppOut): RiskLevel { return (a.risk_level ?? 'Medium') as RiskLevel }
function appPqc(a: AppOut) { return (a.pqc_readiness_score ?? 0) > 50 }
function appRating(a: AppOut) { return a.rating ?? 0 }
function appAudit(a: AppOut) {
  return new Date(a.submitted_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}

// ── App Card ──────────────────────────────────────────────────────────────────
const AppCard: React.FC<{ app: AppOut; onViewDetails: (app: AppOut) => void }> = ({ app, onViewDetails }) => {
  const score = appScore(app)
  const risk = appRisk(app)
  const pqc = appPqc(app)
  const hasResults = app.security_score != null

  return (
    <Card className="group flex flex-col transition-all duration-200 hover:-translate-y-0.5 hover:shadow-md">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-2">
          <CardTitle className="text-sm leading-snug">{appName(app)}</CardTitle>
          {app.rating != null && (
            <div className="flex shrink-0 items-center gap-1">
              <StarFilled />
              <span className="font-mono text-[10px] text-muted-foreground">{appRating(app).toFixed(1)}</span>
            </div>
          )}
        </div>
        <p className="font-mono text-[10px] text-muted-foreground/70">{app.package_name}</p>
        {app.description && (
          <p className="pt-0.5 text-[11px] leading-relaxed text-muted-foreground line-clamp-2">{app.description}</p>
        )}
        <div className="flex items-center gap-2 pt-1">
          {app.category && <Badge variant="secondary">{app.category}</Badge>}
          {app.install_count != null && (
            <span className="font-mono text-[10px] text-muted-foreground">{app.install_count.toLocaleString()} installs</span>
          )}
        </div>
      </CardHeader>

      <CardContent className="flex flex-col gap-3 pt-0">
        {hasResults ? (
          <>
            <div>
              <div className="mb-1.5 flex items-center justify-between">
                <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">Security Score</span>
                <span className={`font-mono text-sm font-bold ${scoreColor(score)}`}>{score}</span>
              </div>
              <Progress value={score} indicatorClassName={scoreBarColor(score)} />
            </div>
            <div className="flex flex-col gap-0">
              {[
                { label: 'Risk Level', value: <Badge variant={riskVariant(risk)}>{risk}</Badge> },
                {
                  label: 'PQC Ready',
                  value: pqc
                    ? <span className="flex items-center gap-1 font-mono text-[11px] font-semibold text-emerald-500 dark:text-emerald-400"><Check size={12} strokeWidth={2.5} /> Yes</span>
                    : <span className="flex items-center gap-1 font-mono text-[11px] font-semibold text-destructive"><X size={11} strokeWidth={2.5} /> No</span>,
                },
                {
                  label: 'Last Audit',
                  value: <span className="font-mono text-[10px] text-muted-foreground">{appAudit(app)}</span>,
                },
              ].map(({ label, value }) => (
                <div key={label} className="flex items-center justify-between border-b border-border/40 py-2 last:border-0">
                  <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{label}</span>
                  {value}
                </div>
              ))}
            </div>
          </>
        ) : (
          <div className="flex flex-col gap-2 rounded-md bg-muted/20 px-3 py-3 text-center">
            <span className="font-mono text-[10px] capitalize text-muted-foreground">
              {app.scan_status === 'pending' ? 'Scan pending…' : app.scan_status}
            </span>
          </div>
        )}
        <Button variant="outline" size="sm" className="mt-1 w-full gap-1.5 text-xs" onClick={() => onViewDetails(app)}>
          View Details <ArrowRight size={12} />
        </Button>
      </CardContent>
    </Card>
  )
}

const FilterPill: React.FC<{ label: string; active: boolean; onClick: () => void }> = ({ label, active, onClick }) => (
  <button
    onClick={onClick}
    className={[
      'rounded-full border px-3 py-1 font-mono text-[10px] uppercase tracking-wider',
      'transition-colors duration-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
      active
        ? 'border-foreground bg-foreground text-background'
        : 'border-border bg-background text-muted-foreground hover:border-foreground/40 hover:text-foreground',
    ].join(' ')}
  >
    {label}
  </button>
)

type SortKey = 'recent' | 'score' | 'rating' | 'name'

export const BrowseAppsPage: React.FC = () => {
  const [query, setQuery] = useState('')
  const [debouncedQuery, setDebouncedQuery] = useState('')
  const [risk, setRisk] = useState<RiskLevel | 'All'>('All')
  const [pqcOnly, setPqcOnly] = useState(false)
  const [sortBy, setSortBy] = useState<SortKey>('recent')
  const [apps, setApps] = useState<AppOut[]>([])
  // Derive loading: null = never fetched, string = last successfully fetched query
  const [fetchedQuery, setFetchedQuery] = useState<string | null>(null)
  const loading = fetchedQuery === null || fetchedQuery !== debouncedQuery
  const [selectedApp, setSelectedApp] = useState<AppOut | null>(null)
  const [detailOpen, setDetailOpen] = useState(false)

  useEffect(() => {
    const t = setTimeout(() => setDebouncedQuery(query), 400)
    return () => clearTimeout(t)
  }, [query])

  // All setState calls live inside Promise callbacks – never synchronously in the effect body
  useEffect(() => {
    let cancelled = false
    appsApi.list(debouncedQuery, 0, 10000, sortBy)
      .then(data => { if (!cancelled) { setApps(data); setFetchedQuery(debouncedQuery) } })
      .catch(()  => { if (!cancelled) setFetchedQuery(debouncedQuery) })
    return () => { cancelled = true }
  }, [debouncedQuery, sortBy])

  const filtered = useMemo(() => apps
    .filter(a => {
      const matchR = risk === 'All' || appRisk(a) === risk
      const matchP = !pqcOnly || appPqc(a)
      return matchR && matchP
    }), [apps, risk, pqcOnly])

  const analyzedApps = apps.filter(a => a.security_score != null)
  const stats = [
    { label: 'Total Apps', value: apps.length, color: 'text-foreground' },
    { label: 'Secure Apps', value: analyzedApps.filter(a => appRisk(a) === 'Low').length, color: 'text-emerald-500 dark:text-emerald-400' },
    { label: 'PQC Ready', value: analyzedApps.filter(appPqc).length, color: 'text-primary' },
    { label: 'Avg. Score', value: analyzedApps.length ? Math.round(analyzedApps.reduce((s, a) => s + appScore(a), 0) / analyzedApps.length) : 0, color: 'text-amber-500' },
    { label: 'Showing', value: filtered.length, color: 'text-muted-foreground' },
  ]

  return (
    <div className="flex flex-col gap-5 p-6">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        {stats.map(s => (
          <Card key={s.label}>
            <CardContent className="p-4">
              <p className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">{s.label}</p>
              <p className={`mt-1 font-mono text-2xl font-bold leading-none ${s.color}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="flex flex-col gap-3">
        <Input
          placeholder="Search by app name or package name…"
          value={query}
          onChange={e => setQuery(e.target.value)}
          icon={<Search size={14} />}
          className="max-w-lg"
        />
        <div className="flex flex-wrap items-center gap-2">
          <span className="flex items-center gap-1 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
            <ListFilter size={12} /> Risk:
          </span>
          {(['All', 'Low', 'Medium', 'High'] as const).map(r => (
            <FilterPill key={r} label={r} active={risk === r} onClick={() => setRisk(r)} />
          ))}
          <div className="mx-1 h-4 w-px bg-border" />
          <FilterPill label="PQC Only" active={pqcOnly} onClick={() => setPqcOnly(v => !v)} />
          <div className="mx-1 h-4 w-px bg-border" />
          <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">Sort:</span>
          {([['recent', 'Recently Added'], ['score', 'Score'], ['rating', 'Rating'], ['name', 'Name']] as [SortKey, string][]).map(([k, label]) => (
            <FilterPill key={k} label={label} active={sortBy === k} onClick={() => setSortBy(k)} />
          ))}
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-16">
          <span role="status" aria-label="Loading applications"
            className="h-5 w-5 animate-spin rounded-full border-2 border-foreground border-t-transparent" />
        </div>
      ) : filtered.length > 0 ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {filtered.map(app => (
            <AppCard key={app.id} app={app} onViewDetails={a => { setSelectedApp(a); setDetailOpen(true) }} />
          ))}
        </div>
      ) : (
        <Card>
          <CardContent className="flex flex-col items-center justify-center gap-2 py-16">
            <p className="text-sm font-medium text-foreground">No applications found</p>
            <p className="text-xs text-muted-foreground">
              {query
                ? <>No results for <span className="font-mono">"{query}"</span> — try adjusting your filters.</>
                : 'No applications in the database yet.'}
            </p>
            <Button variant="outline" size="sm" className="mt-2"
              onClick={() => { setQuery(''); setRisk('All'); setPqcOnly(false) }}>
              Clear filters
            </Button>
          </CardContent>
        </Card>
      )}

      <AppDetailSheet app={selectedApp} open={detailOpen} onClose={() => setDetailOpen(false)} />
    </div>
  )
}
