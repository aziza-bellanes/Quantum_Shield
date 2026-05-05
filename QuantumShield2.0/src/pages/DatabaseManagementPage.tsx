import React, { useState, useEffect, useRef, useCallback } from 'react'
import { RefreshCw, Download, Upload, Database, CheckCircle2, XCircle, Loader2, Clock } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { databasesApi, ApiError } from '../lib/api'
import type { KnowledgeBaseOut, SyncJobOut } from '../lib/api'
import { formatDateTime } from '../lib/utils'

// ── Size helpers ───────────────────────────────────────────────────────────────
function parseSize(s: string | null): number {
  if (!s) return 0
  const m = s.match(/([\d.]+)\s*(GB|MB|KB)/i)
  if (!m) return 0
  const n = parseFloat(m[1])
  const u = m[2].toUpperCase()
  if (u === 'GB') return n * 1e9
  if (u === 'MB') return n * 1e6
  return n * 1e3
}

function formatTotalSize(bytes: number): string {
  if (bytes === 0) return '—'
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(0)} MB`
  return `${(bytes / 1e3).toFixed(0)} KB`
}

function dbStatusVariant(s: string) {
  if (s === 'synced') return 'success' as const
  if (s === 'syncing') return 'warning' as const
  return 'destructive' as const
}

function jobStatusVariant(s: string) {
  if (s === 'success') return 'success' as const
  if (s === 'running') return 'warning' as const
  return 'destructive' as const
}

function JobStatusIcon({ status }: { status: string }) {
  if (status === 'success') return <CheckCircle2 size={12} className="text-green-500" />
  if (status === 'running') return <Loader2 size={12} className="animate-spin text-yellow-500" />
  return <XCircle size={12} className="text-red-500" />
}

function formatDuration(started: string, finished: string | null): string {
  if (!finished) return 'running…'
  const ms = new Date(finished).getTime() - new Date(started).getTime()
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`
}

function formatDelta(before: number | null, after: number | null): string {
  if (before === null || after === null) return '—'
  const d = after - before
  if (d === 0) return '±0'
  return d > 0 ? `+${d.toLocaleString()}` : d.toLocaleString()
}

// ── Component ─────────────────────────────────────────────────────────────────
export const DatabaseManagementPage: React.FC = () => {
  const [databases, setDatabases] = useState<KnowledgeBaseOut[]>([])
  const [jobs, setJobs] = useState<SyncJobOut[]>([])
  const [loadingDbs, setLoadingDbs] = useState(true)
  const [loadingJobs, setLoadingJobs] = useState(true)

  const [syncingAll, setSyncingAll] = useState(false)
  const [syncingId, setSyncingId] = useState<number | null>(null)
  const [exportingId, setExportingId] = useState<number | null>(null)
  const [importingId, setImportingId] = useState<number | null>(null)
  const fileInputRefs = useRef<Record<number, HTMLInputElement | null>>({})

  const [syncInterval, setSyncInterval] = useState('6h')
  const [backupRetention, setBackupRetention] = useState('30d')
  const [saved, setSaved] = useState(false)
  const [savingConfig, setSavingConfig] = useState(false)

  // ── Data fetching ──────────────────────────────────────────────────────────
  const refreshDbs = useCallback(() =>
    databasesApi.list().then(setDatabases).catch(() => {}), [])

  const refreshJobs = useCallback(() =>
    databasesApi.listJobs().then(setJobs).catch(() => {}), [])

  const refreshAll = useCallback(async () => {
    await Promise.all([refreshDbs(), refreshJobs()])
  }, [refreshDbs, refreshJobs])

  useEffect(() => {
    Promise.all([
      databasesApi.list().then(setDatabases).finally(() => setLoadingDbs(false)),
      databasesApi.listJobs().then(setJobs).finally(() => setLoadingJobs(false)),
      databasesApi.getConfig().then(c => {
        setSyncInterval(c.sync_interval)
        setBackupRetention(c.backup_retention)
      }),
    ]).catch(() => {})
  }, [])

  // Poll every 3 s while any KB is syncing or any job is running
  useEffect(() => {
    const hasActive =
      databases.some(d => d.status === 'syncing') ||
      jobs.some(j => j.status === 'running')
    if (!hasActive) return
    const id = setInterval(refreshAll, 3000)
    return () => clearInterval(id)
  }, [databases, jobs, refreshAll])

  // ── Derived stats ──────────────────────────────────────────────────────────
  const totalRecords = databases.reduce((s, d) => s + d.records, 0)
  const syncedCount = databases.filter(d => d.status === 'synced').length
  const cveRecords = databases.find(d => d.name.includes('CVE'))?.records ?? 0
  const totalSize = formatTotalSize(databases.reduce((s, d) => s + parseSize(d.size), 0))

  // ── Handlers ───────────────────────────────────────────────────────────────
  const handleSyncAll = async () => {
    setSyncingAll(true)
    try {
      const updated = await databasesApi.syncAll()
      setDatabases(updated)
      await refreshJobs()
    } catch { /* ignore */ }
    finally { setSyncingAll(false) }
  }

  const handleSync = async (id: number) => {
    setSyncingId(id)
    try {
      const updated = await databasesApi.sync(id)
      setDatabases(prev => prev.map(d => d.id === id ? updated : d))
      await refreshJobs()
    } catch { /* ignore */ }
    finally { setSyncingId(null) }
  }

  const handleExport = async (id: number, name: string) => {
    setExportingId(id)
    try {
      await databasesApi.exportDb(id, name)
      await refreshJobs()
    } catch { /* ignore */ }
    finally { setExportingId(null) }
  }

  const handleImportClick = (id: number) => fileInputRefs.current[id]?.click()

  const handleFileSelect = async (id: number, e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setImportingId(id)
    try {
      const updated = await databasesApi.importDb(id, file)
      setDatabases(prev => prev.map(d => d.id === id ? updated : d))
      await refreshJobs()
    } catch (err) {
      console.error('Import failed', err instanceof ApiError ? err.message : err)
    } finally {
      setImportingId(null)
      e.target.value = ''
    }
  }

  const handleSaveConfig = async () => {
    setSavingConfig(true)
    try {
      await databasesApi.saveConfig(syncInterval, backupRetention)
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch { /* ignore */ }
    finally { setSavingConfig(false) }
  }

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className="flex flex-col gap-5 p-6">

      {/* Stats */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {[
          { label: 'Total Records', value: loadingDbs ? '…' : totalRecords.toLocaleString() },
          { label: 'Synced DBs',    value: loadingDbs ? '…' : `${syncedCount} / ${databases.length}` },
          { label: 'CVE Records',   value: loadingDbs ? '…' : cveRecords.toLocaleString() },
          { label: 'Total Size',    value: loadingDbs ? '…' : totalSize },
        ].map(s => (
          <Card key={s.label}>
            <CardContent className="p-4">
              <p className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">{s.label}</p>
              <p className="mt-1 font-mono text-2xl font-bold leading-none text-foreground">{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Knowledge Bases */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm font-semibold">Knowledge Bases</CardTitle>
              <CardDescription className="text-xs">Manage vulnerability and cryptography databases</CardDescription>
            </div>
            <Button size="sm" className="gap-1.5 h-8 text-xs" onClick={handleSyncAll} disabled={syncingAll} aria-busy={syncingAll}>
              {syncingAll
                ? <><span aria-hidden className="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent" /> Syncing…</>
                : <><RefreshCw size={12} /> Sync All</>}
            </Button>
          </div>
        </CardHeader>
        <CardContent className="flex flex-col gap-3 pt-0">
          {loadingDbs ? (
            <p className="text-xs text-muted-foreground px-1">Loading databases…</p>
          ) : databases.map(db => (
            <div key={db.id} className="rounded-lg border border-border/60 p-4">
              <input
                type="file"
                accept=".json,.csv"
                className="hidden"
                ref={el => { fileInputRefs.current[db.id] = el }}
                onChange={e => handleFileSelect(db.id, e)}
              />
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <Database size={13} className="shrink-0 text-muted-foreground" />
                    <h3 className="text-sm font-semibold text-foreground">{db.name}</h3>
                    <Badge variant={dbStatusVariant(db.status)} className="capitalize gap-1">
                      {db.status === 'syncing' && <span aria-hidden className="h-2 w-2 animate-spin rounded-full border-2 border-current border-t-transparent" />}
                      {db.status}
                    </Badge>
                  </div>
                  <div className="mt-1.5 flex flex-wrap gap-4 text-[10px] font-mono text-muted-foreground">
                    <span>{db.type}</span>
                    <span>{db.records.toLocaleString()} records</span>
                    {db.size && <span>{db.size}</span>}
                    {db.source && <span>Source: {db.source}</span>}
                    <span>Last sync: {db.last_sync ? formatDateTime(db.last_sync) : '—'}</span>
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-1.5">
                  <Button
                    variant="ghost" size="sm" className="h-7 gap-1.5 px-2 text-xs"
                    onClick={() => handleSync(db.id)}
                    disabled={syncingId === db.id || db.status === 'syncing'}
                  >
                    <RefreshCw size={11} className={syncingId === db.id || db.status === 'syncing' ? 'animate-spin' : ''} />
                    {syncingId === db.id ? 'Syncing…' : 'Sync'}
                  </Button>
                  <Button
                    variant="ghost" size="sm" className="h-7 gap-1.5 px-2 text-xs"
                    onClick={() => handleExport(db.id, db.name)}
                    disabled={exportingId === db.id}
                  >
                    <Download size={11} />
                    {exportingId === db.id ? 'Exporting…' : 'Export'}
                  </Button>
                  <Button
                    variant="ghost" size="sm" className="h-7 gap-1.5 px-2 text-xs"
                    onClick={() => handleImportClick(db.id)}
                    disabled={importingId === db.id}
                  >
                    <Upload size={11} />
                    {importingId === db.id ? 'Importing…' : 'Import'}
                  </Button>
                </div>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Sync Job History */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm font-semibold">Sync Job History</CardTitle>
              <CardDescription className="text-xs">Real-time log of all sync, import, and export operations</CardDescription>
            </div>
            <Button variant="ghost" size="sm" className="h-7 gap-1.5 px-2 text-xs" onClick={refreshAll}>
              <RefreshCw size={11} />
              Refresh
            </Button>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border">
                  {['Operation', 'Knowledge Base', 'Status', 'Records Δ', 'Duration', 'Started', 'Triggered By'].map(h => (
                    <th key={h} className="bg-muted/30 px-4 py-2.5 text-left font-mono text-[10px] uppercase tracking-widest text-muted-foreground whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {loadingJobs ? (
                  <tr>
                    <td colSpan={7} className="px-4 py-6 text-center text-xs text-muted-foreground">Loading…</td>
                  </tr>
                ) : jobs.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-4 py-6 text-center text-xs text-muted-foreground">No jobs yet — trigger a sync to see history</td>
                  </tr>
                ) : jobs.map(job => (
                  <tr key={job.id} className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-3 font-mono text-muted-foreground capitalize">{job.operation}</td>
                    <td className="px-4 py-3 font-medium text-foreground">{job.kb_name}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <JobStatusIcon status={job.status} />
                        <Badge variant={jobStatusVariant(job.status)} className="capitalize">{job.status}</Badge>
                      </div>
                    </td>
                    <td className="px-4 py-3 font-mono text-muted-foreground">
                      <span className={
                        job.records_after !== null && job.records_before !== null
                          ? (job.records_after - job.records_before) > 0 ? 'text-green-500' : 'text-muted-foreground'
                          : 'text-muted-foreground'
                      }>
                        {formatDelta(job.records_before, job.records_after)}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-muted-foreground whitespace-nowrap">
                      <span className="flex items-center gap-1">
                        {job.status === 'running' && <Clock size={10} className="animate-pulse" />}
                        {formatDuration(job.started_at, job.finished_at)}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-muted-foreground whitespace-nowrap">{formatDateTime(job.started_at)}</td>
                    <td className="px-4 py-3">
                      <Badge variant={job.triggered_by === 'scheduler' ? 'secondary' : 'outline'} className="text-[10px]">
                        {job.triggered_by}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Sync configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-semibold">Sync Configuration</CardTitle>
          <CardDescription className="text-xs">Configure automatic sync intervals and data retention. Changes take effect within 60 s.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                Auto-sync Interval
              </label>
              <select
                value={syncInterval}
                onChange={e => setSyncInterval(e.target.value)}
                className="h-8 w-full rounded-lg border border-input bg-transparent px-2.5 font-mono text-xs text-foreground outline-none focus:border-ring"
              >
                <option value="1h">Every 1 hour</option>
                <option value="6h">Every 6 hours</option>
                <option value="12h">Every 12 hours</option>
                <option value="24h">Every 24 hours</option>
              </select>
            </div>
            <div>
              <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                Backup Retention
              </label>
              <select
                value={backupRetention}
                onChange={e => setBackupRetention(e.target.value)}
                className="h-8 w-full rounded-lg border border-input bg-transparent px-2.5 font-mono text-xs text-foreground outline-none focus:border-ring"
              >
                <option value="7d">7 days</option>
                <option value="30d">30 days</option>
                <option value="90d">90 days</option>
                <option value="365d">1 year</option>
              </select>
            </div>
          </div>
          <div>
            <Button size="sm" onClick={handleSaveConfig} disabled={savingConfig} aria-busy={savingConfig} className="h-8 gap-1.5 text-xs">
              {savingConfig
                ? <><span aria-hidden className="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent" /> Saving…</>
                : saved ? 'Saved!' : 'Save Configuration'}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
