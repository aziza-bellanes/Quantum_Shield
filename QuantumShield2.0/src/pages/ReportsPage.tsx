import React, { useState, useMemo, useEffect, useCallback } from 'react'
import { Download, FileBarChart2, CheckCircle2, BarChart3, Calculator, RefreshCw } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { useAuth } from '../context/AuthContext'
import { reportsApi } from '../lib/api'
import type { ReportOut } from '../lib/api'
import type { ReportType, ReportStatus } from '../lib/types'
import { formatDate } from '../lib/utils'
import { TlsBarChart } from '../components/charts/TlsBarChart'
import { RiskDonutChart } from '../components/charts/RiskDonutChart'
import type { TlsEntry, RiskEntry } from '../lib/types'

function typeBadgeVariant(type: string) {
  const map: Record<string, 'default' | 'secondary' | 'outline'> = {
    weekly: 'outline',
    monthly: 'secondary',
    quarterly: 'default',
    custom: 'outline',
  }
  return map[type] ?? 'outline'
}

function statusBadgeVariant(status: string) {
  if (status === 'ready') return 'success' as const
  if (status === 'generating') return 'warning' as const
  return 'destructive' as const
}

const TYPE_COLORS: Record<string, string> = {
  weekly: '#3b82f6',
  monthly: '#8b5cf6',
  quarterly: '#f59e0b',
  custom: '#6b7280',
}

const STATUS_COLORS: Record<string, string> = {
  ready: '#22c55e',
  generating: '#f59e0b',
  failed: '#ef4444',
}

export const ReportsPage: React.FC = () => {
  const { user } = useAuth()
  const [reports, setReports] = useState<ReportOut[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState<ReportType | 'all'>('all')
  const [statusFilter, setStatusFilter] = useState<ReportStatus | 'all'>('all')
  const [downloadingId, setDownloadingId] = useState<number | null>(null)
  const [regenerating, setRegenerating] = useState(false)

  const loadReports = useCallback(() => {
    setLoading(true)
    reportsApi.list()
      .then(setReports)
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { loadReports() }, [loadReports])

  const handleRegenerate = async () => {
    setRegenerating(true)
    try {
      await reportsApi.regenerate()
      await loadReports()
    } catch { /* ignore */ }
    finally { setRegenerating(false) }
  }

  const filtered = useMemo(() => {
    return reports.filter(r => {
      const matchSearch = r.title.toLowerCase().includes(search.toLowerCase())
      const matchType = typeFilter === 'all' || r.type === typeFilter
      const matchStatus = statusFilter === 'all' || r.status === statusFilter
      return matchSearch && matchType && matchStatus
    })
  }, [reports, search, typeFilter, statusFilter])

  const totalApps = reports.reduce((s, r) => s + r.apps_count, 0)
  const avgApps = reports.length ? Math.round(totalApps / reports.length) : 0
  const readyCount = reports.filter(r => r.status === 'ready').length

  // Chart data
  const typeChartData: TlsEntry[] = useMemo(() => {
    const counts: Record<string, number> = {}
    reports.forEach(r => { counts[r.type] = (counts[r.type] ?? 0) + 1 })
    return Object.entries(counts).map(([version, count]) => ({
      version,
      count,
      color: TYPE_COLORS[version] ?? '#6b7280',
    }))
  }, [reports])

  const statusChartData: RiskEntry[] = useMemo(() => {
    const counts: Record<string, number> = {}
    reports.forEach(r => { counts[r.status] = (counts[r.status] ?? 0) + 1 })
    return Object.entries(counts).map(([name, value]) => ({
      name: name.charAt(0).toUpperCase() + name.slice(1),
      value,
      color: STATUS_COLORS[name] ?? '#6b7280',
      fill: STATUS_COLORS[name] ?? '#6b7280',
    }))
  }, [reports])

  const handleDownload = async (r: ReportOut) => {
    if (r.status !== 'ready') return
    setDownloadingId(r.id)
    try {
      await reportsApi.download(r.id, r.title)
    } catch { /* ignore */ }
    finally { setDownloadingId(null) }
  }

  return (
    <div className="flex flex-col gap-5 p-6">
      {/* KPI Stats */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {[
          {
            label: 'Total Reports',
            value: loading ? '…' : reports.length,
            icon: <FileBarChart2 size={16} className="text-blue-500" />,
            iconBg: 'border-blue-500/20 bg-blue-500/10',
            sub: 'All time',
          },
          {
            label: 'Ready',
            value: loading ? '…' : readyCount,
            icon: <CheckCircle2 size={16} className="text-emerald-500 dark:text-emerald-400" />,
            iconBg: 'border-emerald-500/20 bg-emerald-500/10',
            sub: 'Available to download',
          },
          {
            label: 'Apps Analyzed',
            value: loading ? '…' : totalApps.toLocaleString(),
            icon: <BarChart3 size={16} className="text-violet-500" />,
            iconBg: 'border-violet-500/20 bg-violet-500/10',
            sub: 'Across all reports',
          },
          {
            label: 'Avg Apps / Report',
            value: loading ? '…' : avgApps,
            icon: <Calculator size={16} className="text-amber-500" />,
            iconBg: 'border-amber-500/20 bg-amber-500/10',
            sub: 'Per report average',
          },
        ].map(s => (
          <Card key={s.label} className="transition-all hover:-translate-y-0.5 hover:shadow-sm">
            <CardContent className="flex items-center justify-between p-5">
              <div>
                <p className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">{s.label}</p>
                <p className="mt-1.5 font-mono text-2xl font-bold leading-none text-foreground">{s.value}</p>
                <p className="mt-1.5 text-[11px] text-muted-foreground">{s.sub}</p>
              </div>
              <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border ${s.iconBg}`}>
                {s.icon}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Charts */}
      {!loading && reports.length > 0 && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <TlsBarChart
            data={typeChartData}
            title="Report Type Distribution"
            description="Breakdown of reports by category"
          />
          <RiskDonutChart
            data={statusChartData}
            title="Report Status"
            description="Overview of report generation states"
          />
        </div>
      )}

      {/* Reports list */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <CardTitle className="text-sm font-semibold">Security Reports</CardTitle>
              <CardDescription className="text-xs">Download and review generated security analyses</CardDescription>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Input
                placeholder="Search reports…"
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="h-7 w-40 text-xs"
              />
              <select
                value={typeFilter}
                onChange={e => setTypeFilter(e.target.value as ReportType | 'all')}
                className="h-7 rounded-lg border border-input bg-transparent px-2 font-mono text-[11px] text-foreground outline-none focus:border-ring"
              >
                <option value="all">All types</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
                {user?.role !== 'end_user' && <option value="quarterly">Quarterly</option>}
                {user?.role !== 'end_user' && <option value="custom">Custom</option>}
              </select>
              <select
                value={statusFilter}
                onChange={e => setStatusFilter(e.target.value as ReportStatus | 'all')}
                className="h-7 rounded-lg border border-input bg-transparent px-2 font-mono text-[11px] text-foreground outline-none focus:border-ring"
              >
                <option value="all">All statuses</option>
                <option value="ready">Ready</option>
                <option value="generating">Generating</option>
              </select>
              {user?.role === 'admin' && (
                <Button
                  variant="outline" size="sm" className="h-7 gap-1.5 text-xs"
                  onClick={handleRegenerate} disabled={regenerating} aria-busy={regenerating}
                  title="Regenerate all reports from current app data"
                >
                  <RefreshCw size={11} className={regenerating ? 'animate-spin' : ''} />
                  {regenerating ? 'Regenerating…' : 'Regenerate'}
                </Button>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="flex flex-col items-center gap-2 py-12 text-center">
              <p className="text-sm text-muted-foreground">Loading reports…</p>
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center gap-2 py-12 text-center">
              <FileBarChart2 size={28} className="text-muted-foreground/30" />
              <p className="text-sm text-muted-foreground">No reports match your filters</p>
            </div>
          ) : (
            <div className="flex flex-col divide-y divide-border/50">
              {filtered.map(r => (
                <div key={r.id} className="flex flex-col gap-2 px-4 py-3 transition-colors hover:bg-muted/20 sm:flex-row sm:items-center sm:justify-between">
                  <div className="flex items-center gap-3">
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-muted">
                      <FileBarChart2 size={15} className="text-muted-foreground" />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-foreground">{r.title}</p>
                      <p className="font-mono text-[10px] text-muted-foreground">{formatDate(r.date)}</p>
                    </div>
                  </div>
                  <div className="flex flex-wrap items-center gap-2 sm:shrink-0">
                    <Badge variant={typeBadgeVariant(r.type)} className="capitalize font-mono text-[10px]">{r.type}</Badge>
                    {r.apps_count > 0 && (
                      <span className="font-mono text-[10px] text-muted-foreground">{r.apps_count} apps</span>
                    )}
                    <Badge variant={statusBadgeVariant(r.status)} className="capitalize">{r.status}</Badge>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 gap-1.5 px-2 text-xs"
                      disabled={r.status !== 'ready' || downloadingId === r.id}
                      onClick={() => handleDownload(r)}
                    >
                      <Download size={11} />
                      {downloadingId === r.id ? 'Downloading…' : 'Download'}
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
