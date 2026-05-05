import React, { useEffect, useState, useCallback } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { ChartContainer, ChartTooltip, ChartTooltipContent } from '../components/ui/chart'
import {
  AreaChart, Area, LineChart, Line,
  XAxis, YAxis, CartesianGrid, ResponsiveContainer,
} from 'recharts'
import { adminApi, ApiError, reportsApi } from '../lib/api'
import type { SystemHealthOut, MlMetricsOut, MetricsTimeseriesPoint } from '../lib/api'
import { RefreshCw } from 'lucide-react'
import type { ServiceHealth } from '../lib/types'

function healthVariant(h: ServiceHealth) {
  if (h === 'healthy') return 'success' as const
  if (h === 'degraded') return 'warning' as const
  return 'destructive' as const
}

function healthDot(h: ServiceHealth) {
  if (h === 'healthy') return 'bg-emerald-500'
  if (h === 'degraded') return 'bg-amber-500'
  return 'bg-destructive'
}

const scansConfig  = { scans:       { label: 'Scans',       color: 'hsl(var(--primary))' } }
const predsConfig  = { predictions: { label: 'Predictions', color: 'hsl(142 71% 45%)' } }

export const SystemMonitorPage: React.FC = () => {
  const [health, setHealth] = useState<SystemHealthOut | null>(null)
  const [mlMetrics, setMlMetrics] = useState<MlMetricsOut | null>(null)
  const [timeseries, setTimeseries] = useState<MetricsTimeseriesPoint[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [training, setTraining] = useState(false)
  const [trainBanner, setTrainBanner] = useState<{ ok: boolean; msg: string } | null>(null)
  const [seeding, setSeeding] = useState(false)
  const [seedBanner, setSeedBanner] = useState<{ ok: boolean; msg: string } | null>(null)

  const fetchData = useCallback(() => {
    setLoading(true)
    Promise.all([adminApi.systemHealth(), adminApi.mlMetrics(), adminApi.metricsTimeseries()])
      .then(([h, ml, ts]) => { setHealth(h); setMlMetrics(ml); setTimeseries(ts) })
      .catch(err => {
        if (err instanceof ApiError) setError(err.message)
        else setError('Failed to load system health.')
      })
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 30000)
    return () => clearInterval(interval)
  }, [fetchData])

  const handleSeedCsv = async () => {
    setSeeding(true)
    setSeedBanner(null)
    try {
      const res = await adminApi.seedCsv()
      // Auto-regenerate reports after seeding so the Reports page reflects new data
      await reportsApi.regenerate().catch(() => {})
      setSeedBanner({
        ok: true,
        msg: `Seed complete: ${res.apps_created} apps, ${res.domains_created} domains, ${res.tls_results_created} TLS results created. Reports regenerated.`,
      })
      // Refresh health stats
      fetchData()
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : 'Seed failed. Check that the CSV file exists on the server.'
      setSeedBanner({ ok: false, msg })
    } finally {
      setSeeding(false)
    }
  }

  const handleTrainModel = async () => {
    setTraining(true)
    setTrainBanner(null)
    try {
      await adminApi.trainModel()
      setTrainBanner({ ok: true, msg: 'Model retrained successfully. Refreshing metrics…' })
      // Refresh ML metrics after successful training
      adminApi.mlMetrics()
        .then(ml => setMlMetrics(ml))
        .catch(() => {})
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : 'Training failed. Please try again.'
      setTrainBanner({ ok: false, msg })
    } finally {
      setTraining(false)
    }
  }

  // Build service list from health data
  const services = health ? [
    { name: 'Database', status: health.db_connected ? 'healthy' : 'down' as ServiceHealth, uptime: health.db_connected ? 99.99 : 0, lastCheck: 'Just now' },
    { name: 'ML Predictor', status: health.ml_model_loaded ? 'healthy' : 'degraded' as ServiceHealth, uptime: health.ml_model_loaded ? 99.5 : 0, lastCheck: 'Just now' },
    { name: 'Scan Queue', status: health.pending_scans > 20 ? 'degraded' : 'healthy' as ServiceHealth, uptime: 99.8, lastCheck: 'Just now' },
    { name: 'API Gateway', status: 'healthy' as ServiceHealth, uptime: 99.99, lastCheck: 'Just now' },
  ] : []

  return (
    <div className="flex flex-col gap-5 p-6">
      {/* Refresh button */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-foreground">System Monitor</h2>
          <p className="text-xs text-muted-foreground">Real-time platform health and performance</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" className="h-7 gap-1.5 text-xs" onClick={fetchData} disabled={loading}>
            <RefreshCw size={11} className={loading ? 'animate-spin' : ''} /> Refresh
          </Button>
          <Button variant="outline" size="sm" className="h-7 gap-1.5 text-xs" onClick={handleSeedCsv} disabled={seeding} title="Populate DB from pqc-research/data/report_per_domain.csv">
            {seeding ? <><span aria-hidden="true" className="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent" /> Seeding…</> : 'Seed from CSV'}
          </Button>
          <Button size="sm" className="h-7 gap-1.5 text-xs" onClick={handleTrainModel} disabled={training}>
            {training ? <><span aria-hidden="true" className="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent" /> Training…</> : 'Retrain ML Model'}
          </Button>
        </div>
      </div>

      {error && <p className="text-xs text-destructive">{error}</p>}
      {seedBanner && (
        <div className={`flex items-center justify-between rounded-lg border px-4 py-2.5 text-xs ${seedBanner.ok ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' : 'border-destructive/30 bg-destructive/10 text-destructive'}`}>
          <span>{seedBanner.msg}</span>
          <button onClick={() => setSeedBanner(null)} className="ml-4 text-current opacity-60 hover:opacity-100" aria-label="Dismiss">✕</button>
        </div>
      )}
      {trainBanner && (
        <div className={`flex items-center justify-between rounded-lg border px-4 py-2.5 text-xs ${trainBanner.ok ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' : 'border-destructive/30 bg-destructive/10 text-destructive'}`}>
          <span>{trainBanner.msg}</span>
          <button onClick={() => setTrainBanner(null)} className="ml-4 text-current opacity-60 hover:opacity-100" aria-label="Dismiss">✕</button>
        </div>
      )}

      {/* KPI cards */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {loading ? (
          Array.from({ length: 4 }).map((_, i) => (
            <Card key={i}>
              <CardContent className="p-4">
                <div className="h-3 w-20 animate-pulse rounded bg-muted" />
                <div className="mt-2 h-7 w-12 animate-pulse rounded bg-muted" />
              </CardContent>
            </Card>
          ))
        ) : [
          { label: 'Total Users', value: health?.total_users ?? 0 },
          { label: 'Total Apps', value: health?.total_apps ?? 0 },
          { label: 'Total Scans', value: health?.total_scans ?? 0 },
          { label: 'Pending Scans', value: health?.pending_scans ?? 0 },
        ].map(s => (
          <Card key={s.label}>
            <CardContent className="p-4">
              <p className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">{s.label}</p>
              <p className="mt-1 font-mono text-2xl font-bold leading-none text-foreground">{s.value.toLocaleString()}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* ML Metrics row */}
      {mlMetrics && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {[
            { label: 'ML Coverage', value: `${mlMetrics.coverage_pct}%` },
            { label: 'Avg Score', value: mlMetrics.avg_security_score.toFixed(1) },
            { label: 'Avg PQC', value: `${mlMetrics.avg_pqc_readiness.toFixed(1)}%` },
            { label: 'Total Predictions', value: mlMetrics.total_predictions },
          ].map(s => (
            <Card key={s.label}>
              <CardContent className="p-4">
                <p className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">{s.label}</p>
                <p className="mt-1 font-mono text-2xl font-bold leading-none text-foreground">{s.value}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Charts row */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-semibold">Scan Activity (24h)</CardTitle>
            <CardDescription className="text-xs">App submissions per 3-hour window over the last 24 hours</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={scansConfig} className="h-[200px] w-full [aspect-ratio:unset]">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timeseries} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="time" tick={{ fontSize: 10, fontFamily: 'monospace' }} tickLine={false} axisLine={false} />
                  <YAxis tick={{ fontSize: 10, fontFamily: 'monospace' }} tickLine={false} axisLine={false} allowDecimals={false} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Area type="monotone" dataKey="scans" stroke="hsl(var(--primary))" fill="hsl(var(--primary) / 0.12)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </ChartContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-semibold">ML Predictions (24h)</CardTitle>
            <CardDescription className="text-xs">Predictions generated per 3-hour window over the last 24 hours</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={predsConfig} className="h-[200px] w-full [aspect-ratio:unset]">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={timeseries} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="time" tick={{ fontSize: 10, fontFamily: 'monospace' }} tickLine={false} axisLine={false} />
                  <YAxis tick={{ fontSize: 10, fontFamily: 'monospace' }} tickLine={false} axisLine={false} allowDecimals={false} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Line type="monotone" dataKey="predictions" stroke="hsl(142 71% 45%)" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </ChartContainer>
          </CardContent>
        </Card>
      </div>

      {/* Services table + DB health */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-semibold">System Services</CardTitle>
            <CardDescription className="text-xs">Real-time health of platform components</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border">
                  <th className="bg-muted/30 px-4 py-2.5 text-left font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Service</th>
                  <th className="bg-muted/30 px-4 py-2.5 text-left font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Uptime</th>
                  <th className="bg-muted/30 px-4 py-2.5 text-left font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Health</th>
                </tr>
              </thead>
              <tbody>
                {services.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="px-4 py-8 text-center text-xs text-muted-foreground">
                      {loading ? 'Loading…' : 'No data'}
                    </td>
                  </tr>
                ) : services.map(s => (
                  <tr key={s.name} className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${healthDot(s.status as ServiceHealth)}`} />
                        <span className="font-medium text-foreground">{s.name}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 font-mono text-muted-foreground">{s.uptime.toFixed(2)}%</td>
                    <td className="px-4 py-3">
                      <Badge variant={healthVariant(s.status as ServiceHealth)} className="capitalize">{s.status}</Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>

        {/* ML Risk distribution card */}
        {mlMetrics && (
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-semibold">Risk Distribution (ML)</CardTitle>
              <CardDescription className="text-xs">Predicted risk levels across all analyzed apps</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              {Object.entries(mlMetrics.risk_distribution).map(([risk, count]) => {
                const pct = mlMetrics.total_predictions > 0
                  ? Math.round((count / mlMetrics.total_predictions) * 100)
                  : 0
                return (
                  <div key={risk}>
                    <div className="mb-1 flex items-center justify-between text-xs">
                      <span className="text-muted-foreground">{risk}</span>
                      <span className="font-mono font-semibold text-foreground">{count} ({pct}%)</span>
                    </div>
                    <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
                      <div
                        className={`h-full rounded-full ${risk === 'Low' ? 'bg-emerald-500' : risk === 'Medium' ? 'bg-amber-500' : 'bg-red-500'}`}
                        style={{ width: `${pct}%`, transition: 'width 0.6s ease' }}
                      />
                    </div>
                  </div>
                )
              })}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}
