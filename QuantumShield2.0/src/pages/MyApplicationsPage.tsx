import React, { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { Package, Upload, RotateCw, Download, ExternalLink } from 'lucide-react'
import { AppDetailSheet } from '../components/AppDetailSheet'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Progress } from '../components/ui/progress'
import { appsApi, ApiError } from '../lib/api'
import type { AppOut } from '../lib/api'
import { useAuth } from '../context/AuthContext'
import { cn, scoreColor, scoreBarColor, riskVariant } from '../lib/utils'
import type { RiskLevel } from '../lib/types'

type AppStatus = 'Analyzed' | 'Analyzing' | 'Failed'

function mapStatus(scanStatus: string): AppStatus {
  if (scanStatus === 'completed') return 'Analyzed'
  if (scanStatus === 'failed') return 'Failed'
  return 'Analyzing'
}

function statusVariant(status: AppStatus) {
  if (status === 'Analyzed') return 'success' as const
  if (status === 'Analyzing') return 'warning' as const
  return 'destructive' as const
}


export const MyApplicationsPage: React.FC = () => {
  const { user } = useAuth()
  const navigate = useNavigate()
  const [apps, setApps] = useState<AppOut[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedApp, setSelectedApp] = useState<AppOut | null>(null)
  const [detailOpen, setDetailOpen] = useState(false)

  const fetchApps = useCallback(() => {
    setLoading(true)
    appsApi.list('', 0, 100)
      .then(all => {
        // Filter to apps owned by current user
        const userId = user ? parseInt(user.id) : null
        const mine = userId != null ? all.filter(a => a.owner_id === userId) : all
        setApps(mine)
      })
      .catch(err => {
        if (err instanceof ApiError) setError(err.message)
        else setError('Failed to load applications.')
      })
      .finally(() => setLoading(false))
  }, [user])

  useEffect(() => {
    fetchApps()
    // Poll every 10s to pick up newly completed scans
    const interval = setInterval(fetchApps, 10000)
    return () => clearInterval(interval)
  }, [fetchApps])

  const analyzed = apps.filter(a => a.scan_status === 'completed' && a.security_score != null)
  const totalVulns = 0 // vulnerabilities not available in list endpoint
  const pqcReady = analyzed.filter(a => (a.pqc_readiness_score ?? 0) > 50).length
  const avgScore = analyzed.length
    ? Math.round(analyzed.reduce((s, a) => s + (a.security_score ?? 0), 0) / analyzed.length)
    : 0

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24 p-6">
        <span role="status" aria-label="Loading applications"
          className="h-5 w-5 animate-spin rounded-full border-2 border-foreground border-t-transparent" />
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-5 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-foreground">My Applications</h2>
          <p className="text-xs text-muted-foreground">Manage and monitor your submitted applications</p>
        </div>
        <Button size="sm" className="gap-1.5 h-8 text-xs" onClick={() => navigate('/analyze')}>
          <Upload size={13} /> Upload New App
        </Button>
      </div>

      {error && (
        <p className="text-xs text-destructive">{error}</p>
      )}

      {/* Stats */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {[
          { label: 'Total Apps', value: apps.length },
          { label: 'Avg Score', value: avgScore },
          { label: 'PQC Ready', value: pqcReady },
          { label: 'Total Vulns', value: totalVulns },
        ].map(s => (
          <Card key={s.label}>
            <CardContent className="p-4">
              <p className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">{s.label}</p>
              <p className="mt-1 font-mono text-2xl font-bold leading-none text-foreground">{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Apps list */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Applications</CardTitle>
          <CardDescription className="text-xs">{apps.length} application{apps.length !== 1 ? 's' : ''} in your portfolio</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3 pt-0">
          {apps.length === 0 ? (
            <div className="flex flex-col items-center gap-3 py-12 text-center">
              <Package size={28} className="text-muted-foreground/30" />
              <p className="text-sm text-muted-foreground">No applications yet</p>
              <p className="text-xs text-muted-foreground">Use the Analyze App page to submit your first app.</p>
            </div>
          ) : (
            apps.map(app => {
              const status = mapStatus(app.scan_status)
              const score = Math.round(app.security_score ?? 0)
              const risk = (app.risk_level ?? 'Medium') as RiskLevel
              const pqc = (app.pqc_readiness_score ?? 0) > 50

              return (
                <div key={app.id} className="rounded-lg border border-border/60 p-4">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                    {/* Left */}
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="text-sm font-semibold text-foreground">
                          {app.app_name ?? app.package_name}
                        </h3>
                        <Badge variant={statusVariant(status)}>{status}</Badge>
                      </div>
                      <p className="mt-0.5 font-mono text-[10px] text-muted-foreground/60">{app.package_name}</p>
                      <div className="mt-1 flex flex-wrap items-center gap-3">
                        {app.category && (
                          <span className="font-mono text-[10px] text-muted-foreground">{app.category}</span>
                        )}
                        <span className="font-mono text-[10px] text-muted-foreground">
                          Submitted {new Date(app.submitted_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}
                        </span>
                      </div>
                    </div>

                    {/* Right — status-dependent content */}
                    {status === 'Analyzed' && app.security_score != null && (
                      <div className="flex shrink-0 flex-col gap-2 sm:items-end">
                        <div className="flex items-center gap-3">
                          <span className={cn('font-mono text-lg font-bold', scoreColor(score))}>{score}</span>
                          <Badge variant={riskVariant(risk)}>{risk}</Badge>
                          <Badge variant={pqc ? 'success' as const : 'destructive'}>
                            {pqc ? 'PQC Ready' : 'No PQC'}
                          </Badge>
                        </div>
                        <Progress value={score} className={cn('h-1.5 w-32', scoreBarColor(score))} />
                        <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground font-mono">
                          PQC score: {Math.round(app.pqc_readiness_score ?? 0)}%
                        </div>
                      </div>
                    )}

                    {status === 'Analyzing' && (
                      <div role="status" aria-label="Analysis in progress"
                        className="flex shrink-0 items-center gap-2 text-xs text-muted-foreground">
                        <span aria-hidden="true" className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" />
                        Analysis in progress…
                      </div>
                    )}

                    {status === 'Failed' && (
                      <div className="flex shrink-0 items-center gap-2">
                        <span className="text-xs text-destructive">Analysis failed</span>
                        <Button variant="outline" size="sm" className="h-7 gap-1.5 text-xs" onClick={fetchApps}>
                          <RotateCw size={11} /> Refresh
                        </Button>
                      </div>
                    )}
                  </div>

                  {/* Actions */}
                  {status === 'Analyzed' && (
                    <div className="mt-3 flex items-center gap-2 border-t border-border/40 pt-3">
                      <Button
                        variant="ghost" size="sm" className="h-7 gap-1.5 px-2 text-xs"
                        onClick={() => { setSelectedApp(app); setDetailOpen(true) }}
                      >
                        <ExternalLink size={11} /> View Details
                      </Button>
                      <Button
                        variant="ghost" size="sm" className="h-7 gap-1.5 px-2 text-xs"
                        onClick={() => navigate(`/apps/${app.id}/report`)}
                      >
                        <Download size={11} /> View Report
                      </Button>
                    </div>
                  )}
                </div>
              )
            })
          )}
        </CardContent>
      </Card>

      <AppDetailSheet app={selectedApp} open={detailOpen} onClose={() => setDetailOpen(false)} />
    </div>
  )
}
