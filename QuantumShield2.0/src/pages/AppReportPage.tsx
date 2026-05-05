import React, { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, PieChart, Pie, Cell,
  RadialBarChart, RadialBar, Tooltip,
} from 'recharts'
import {
  Shield, AlertTriangle, Globe, Cpu, Download, ArrowLeft,
  CheckCircle2, XCircle, Lock, Server, Clock, Tag,
} from 'lucide-react'
import { appsApi } from '../lib/api'
import type { AppOut, TLSResultOut, VulnerabilityOut, DomainOut, MLPredictionOut } from '../lib/api'
import { cn } from '../lib/utils'

// ── Helpers ─────────────────────────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score >= 80) return 'text-emerald-500'
  if (score >= 60) return 'text-yellow-500'
  if (score >= 40) return 'text-orange-500'
  return 'text-red-500'
}

function scoreHex(score: number): string {
  if (score >= 80) return '#22c55e'
  if (score >= 60) return '#eab308'
  if (score >= 40) return '#f97316'
  return '#ef4444'
}

function riskColor(risk: string): string {
  const r = risk.toLowerCase()
  if (r === 'low') return 'bg-emerald-500/10 text-emerald-600 border-emerald-200'
  if (r === 'medium') return 'bg-yellow-500/10 text-yellow-600 border-yellow-200'
  if (r === 'high') return 'bg-red-500/10 text-red-600 border-red-200'
  return 'bg-muted text-muted-foreground border-border'
}

function severityColor(sev: string): string {
  const s = sev.toLowerCase()
  if (s === 'critical') return 'bg-red-600 text-white'
  if (s === 'high') return 'bg-red-500 text-white'
  if (s === 'medium') return 'bg-yellow-500 text-black'
  if (s === 'low') return 'bg-emerald-500 text-white'
  return 'bg-muted text-muted-foreground'
}

// ── Score Ring ───────────────────────────────────────────────────────────────

const ScoreRing: React.FC<{ score: number; label: string; size?: number }> = ({
  score, label, size = 100,
}) => {
  const r = (size - 16) / 2
  const circ = 2 * Math.PI * r
  const offset = circ - (score / 100) * circ
  return (
    <div className="flex flex-col items-center gap-1">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
          <circle cx={size / 2} cy={size / 2} r={r} fill="none"
            stroke="hsl(var(--border))" strokeWidth={10} />
          <circle cx={size / 2} cy={size / 2} r={r} fill="none"
            stroke={scoreHex(score)} strokeWidth={10}
            strokeDasharray={circ} strokeDashoffset={offset}
            strokeLinecap="round" style={{ transition: 'stroke-dashoffset 0.8s ease' }} />
        </svg>
        <span className={cn(
          'absolute inset-0 flex items-center justify-center',
          'font-mono text-2xl font-bold leading-none',
          scoreColor(score)
        )}>
          {Math.round(score)}
        </span>
      </div>
      <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{label}</span>
    </div>
  )
}

// ── Main Report Page ─────────────────────────────────────────────────────────

export const AppReportPage: React.FC = () => {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const appId = Number(id)

  const [app, setApp] = useState<AppOut | null>(null)
  const [tlsResults, setTlsResults] = useState<TLSResultOut[]>([])
  const [vulns, setVulns] = useState<VulnerabilityOut[]>([])
  const [domains, setDomains] = useState<DomainOut[]>([])
  const [prediction, setPrediction] = useState<MLPredictionOut | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (Number.isNaN(appId)) { Promise.resolve().then(() => { setError('Invalid app ID'); setLoading(false) }); return }
    Promise.all([
      appsApi.get(appId),
      appsApi.tls(appId).catch(() => [] as TLSResultOut[]),
      appsApi.vulnerabilities(appId).catch(() => [] as VulnerabilityOut[]),
      appsApi.domains(appId).catch(() => [] as DomainOut[]),
      appsApi.prediction(appId).catch(() => null),
    ]).then(([a, t, v, d, p]) => {
      setApp(a); setTlsResults(t); setVulns(v); setDomains(d); setPrediction(p)
    }).catch(err => {
      setError(err instanceof Error ? err.message : 'Failed to load report')
    }).finally(() => setLoading(false))
  }, [appId])

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <span role="status" aria-label="Loading report"
          className="h-6 w-6 animate-spin rounded-full border-2 border-foreground border-t-transparent" />
      </div>
    )
  }

  if (error || !app) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-background p-6">
        <AlertTriangle size={32} className="text-destructive" />
        <p className="text-sm text-destructive">{error ?? 'App not found'}</p>
        <button onClick={() => navigate(-1)} className="text-xs text-muted-foreground underline">
          Go back
        </button>
      </div>
    )
  }

  // ── Derived data ──────────────────────────────────────────────────────────

  const score = Math.round(app.security_score ?? 0)
  const pqcScore = Math.round(app.pqc_readiness_score ?? 0)
  const risk = app.risk_level ?? 'Unknown'

  // TLS version distribution for bar chart
  const tlsVersionCounts: Record<string, number> = {}
  for (const r of tlsResults) {
    const v = r.tls_version ?? 'Unknown'
    tlsVersionCounts[v] = (tlsVersionCounts[v] ?? 0) + 1
  }
  const TLS_COLORS: Record<string, string> = {
    'TLSv1': '#ef4444', 'TLSv1.0': '#ef4444',
    'TLSv1.1': '#f97316', 'TLSv1.2': '#eab308', 'TLSv1.3': '#22c55e',
    'Unknown': '#94a3b8',
  }
  const tlsBarData = Object.entries(tlsVersionCounts).map(([version, count]) => ({
    version,
    count,
    fill: TLS_COLORS[version] ?? '#6366f1',
  }))

  // Vulnerability severity distribution for donut
  const sevCounts: Record<string, number> = {}
  for (const v of vulns) {
    const s = v.severity ?? 'Unknown'
    sevCounts[s] = (sevCounts[s] ?? 0) + 1
  }
  const SEV_COLORS: Record<string, string> = {
    Critical: '#dc2626', High: '#ef4444', Medium: '#eab308',
    Low: '#22c55e', Info: '#6366f1', Unknown: '#94a3b8',
  }
  const sevDonutData = Object.entries(sevCounts).map(([name, value]) => ({
    name, value, fill: SEV_COLORS[name] ?? '#94a3b8',
  }))

  const pqcReady = pqcScore > 50
  const legacyCount = tlsResults.filter(r => r.flag_legacy_tls).length
  const pqcDomains = tlsResults.filter(r => r.supports_pqc).length
  const scanDate = app.submitted_at
    ? new Date(app.submitted_at + (app.submitted_at.endsWith('Z') ? '' : 'Z')).toLocaleDateString('en-US', {
        year: 'numeric', month: 'long', day: 'numeric',
      })
    : '—'

  return (
    <div className="min-h-screen bg-background text-foreground print:bg-white">
      {/* Print styles */}
      <style>{`
        @media print {
          .no-print { display: none !important; }
          .print-break { page-break-before: always; }
          body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        }
      `}</style>

      {/* Toolbar (hidden when printing) */}
      <div className="no-print sticky top-0 z-10 flex items-center justify-between border-b border-border bg-background/95 px-6 py-3 backdrop-blur">
        <button
          onClick={() => navigate(-1)}
          className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
        >
          <ArrowLeft size={14} /> Back
        </button>
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground font-mono">
            {app.app_name ?? app.package_name}
          </span>
          <button
            onClick={() => window.print()}
            className="flex items-center gap-1.5 rounded-md border border-border bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
          >
            <Download size={13} /> Save as PDF
          </button>
        </div>
      </div>

      <div className="mx-auto max-w-5xl px-6 py-8 space-y-8">
        {/* ── Report Header ─────────────────────────────────────────────── */}
        <div className="flex flex-col gap-4 rounded-xl border border-border bg-card p-6 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10">
              <Shield size={22} className="text-primary" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-foreground">
                {app.app_name ?? app.package_name}
              </h1>
              <p className="font-mono text-[11px] text-muted-foreground">{app.package_name}</p>
              <div className="mt-1 flex flex-wrap items-center gap-2">
                {app.category && (
                  <span className="flex items-center gap-1 font-mono text-[10px] text-muted-foreground">
                    <Tag size={10} /> {app.category}
                  </span>
                )}
                <span className="flex items-center gap-1 font-mono text-[10px] text-muted-foreground">
                  <Clock size={10} /> Scanned {scanDate}
                </span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className={cn(
              'rounded-full border px-3 py-1 text-xs font-semibold',
              riskColor(risk)
            )}>
              {risk} Risk
            </span>
            <span className={cn(
              'rounded-full border px-3 py-1 text-xs font-semibold',
              pqcReady
                ? 'bg-emerald-500/10 text-emerald-600 border-emerald-200'
                : 'bg-red-500/10 text-red-600 border-red-200'
            )}>
              {pqcReady ? 'PQC Ready' : 'Not PQC Ready'}
            </span>
          </div>
        </div>

        {/* ── KPI Cards ─────────────────────────────────────────────────── */}
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {[
            { label: 'Security Score', value: `${score}`, icon: Shield, color: 'text-blue-500', bg: 'bg-blue-500/10' },
            { label: 'PQC Readiness', value: `${pqcScore}%`, icon: Lock, color: 'text-violet-500', bg: 'bg-violet-500/10' },
            { label: 'Vulnerabilities', value: String(vulns.length), icon: AlertTriangle, color: 'text-amber-500', bg: 'bg-amber-500/10' },
            { label: 'Domains Scanned', value: String(domains.length), icon: Globe, color: 'text-emerald-500', bg: 'bg-emerald-500/10' },
          ].map(({ label, value, icon: Icon, color, bg }) => (
            <div key={label} className="rounded-xl border border-border bg-card p-4">
              <div className={cn('mb-2 flex h-8 w-8 items-center justify-center rounded-lg', bg)}>
                <Icon size={16} className={color} />
              </div>
              <p className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">{label}</p>
              <p className={cn('mt-0.5 font-mono text-2xl font-bold leading-none', color)}>{value}</p>
            </div>
          ))}
        </div>

        {/* ── Score Rings ────────────────────────────────────────────────── */}
        <div className="rounded-xl border border-border bg-card p-6">
          <h2 className="mb-4 text-sm font-semibold text-foreground">Security Score Overview</h2>
          <div className="flex flex-wrap items-center justify-around gap-8">
            <ScoreRing score={score} label="Security" />
            <ScoreRing score={pqcScore} label="PQC Readiness" />
            {prediction && (
              <ScoreRing score={Math.round(prediction.confidence ?? 0) * 100} label="ML Confidence" />
            )}
            <div className="flex flex-col items-center gap-2">
              <div className={cn(
                'flex h-[100px] w-[100px] items-center justify-center rounded-full border-4',
                risk.toLowerCase() === 'low' ? 'border-emerald-500 bg-emerald-500/10' :
                risk.toLowerCase() === 'medium' ? 'border-yellow-500 bg-yellow-500/10' :
                'border-red-500 bg-red-500/10'
              )}>
                <span className={cn('font-bold text-lg',
                  risk.toLowerCase() === 'low' ? 'text-emerald-600' :
                  risk.toLowerCase() === 'medium' ? 'text-yellow-600' : 'text-red-600'
                )}>{risk}</span>
              </div>
              <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Risk Level</span>
            </div>
          </div>
        </div>

        {/* ── Charts ────────────────────────────────────────────────────── */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          {/* TLS Distribution */}
          <div className="rounded-xl border border-border bg-card p-5">
            <h2 className="mb-1 text-sm font-semibold text-foreground">TLS Version Distribution</h2>
            <p className="mb-4 text-[11px] text-muted-foreground">Protocol versions across scanned domains</p>
            {tlsBarData.length > 0 ? (
              <>
                <div style={{ width: '100%', height: 200 }}>
                  <BarChart width={380} height={200} data={tlsBarData}
                    margin={{ top: 4, right: 4, bottom: 0, left: -16 }} barSize={36}>
                    <CartesianGrid vertical={false} stroke="hsl(var(--border))" strokeOpacity={0.4} />
                    <XAxis dataKey="version" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} />
                    <YAxis tick={{ fontSize: 10 }} tickLine={false} axisLine={false} />
                    <Tooltip
                      contentStyle={{ fontSize: 11, borderRadius: 8, border: '1px solid hsl(var(--border))' }}
                      formatter={(v) => [`${v} domain(s)`, 'Count']}
                    />
                    <Bar dataKey="count" radius={[5, 5, 0, 0]}>
                      {tlsBarData.map((entry, i) => (
                        <Cell key={i} fill={entry.fill} />
                      ))}
                    </Bar>
                  </BarChart>
                </div>
                <div className="mt-3 flex flex-wrap gap-3">
                  {tlsBarData.map(d => (
                    <span key={d.version} className="flex items-center gap-1.5 font-mono text-[10px] text-muted-foreground">
                      <span className="inline-block h-2 w-2 rounded-[2px]" style={{ background: d.fill }} />
                      {d.version}
                    </span>
                  ))}
                </div>
              </>
            ) : (
              <p className="py-8 text-center text-xs text-muted-foreground">No TLS data available</p>
            )}
          </div>

          {/* Vulnerability Severity */}
          <div className="rounded-xl border border-border bg-card p-5">
            <h2 className="mb-1 text-sm font-semibold text-foreground">Vulnerability Severity</h2>
            <p className="mb-4 text-[11px] text-muted-foreground">Distribution of detected vulnerabilities by severity</p>
            {sevDonutData.length > 0 ? (
              <div className="flex items-center gap-5">
                <PieChart width={160} height={160}>
                  <Pie data={sevDonutData} dataKey="value" nameKey="name"
                    cx="50%" cy="50%" innerRadius={48} outerRadius={70} strokeWidth={0}>
                    {sevDonutData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ fontSize: 11, borderRadius: 8, border: '1px solid hsl(var(--border))' }}
                    formatter={(v, n) => [`${v} vuln(s)`, n]}
                  />
                </PieChart>
                <div className="flex flex-1 flex-col gap-2">
                  {sevDonutData.map(d => (
                    <div key={d.name} className="flex items-center justify-between">
                      <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                        <span className="inline-block h-2 w-2 rounded-[2px]" style={{ background: d.fill }} />
                        {d.name}
                      </span>
                      <span className="font-mono text-xs font-semibold text-foreground">{d.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-8 gap-2">
                <CheckCircle2 size={28} className="text-emerald-500" />
                <p className="text-xs text-muted-foreground">No vulnerabilities detected</p>
              </div>
            )}
          </div>
        </div>

        {/* ── TLS Results Table ─────────────────────────────────────────── */}
        {tlsResults.length > 0 && (
          <div className="rounded-xl border border-border bg-card">
            <div className="border-b border-border px-5 py-4">
              <h2 className="text-sm font-semibold text-foreground">TLS Scan Results</h2>
              <p className="text-[11px] text-muted-foreground">{tlsResults.length} domain{tlsResults.length !== 1 ? 's' : ''} analyzed</p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border/50">
                    {['Domain ID', 'TLS Version', 'Cipher Suite', 'Key Exchange', 'PQC', 'Legacy', 'Security Score'].map(h => (
                      <th key={h} className="px-4 py-2.5 text-left font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {tlsResults.map((r, i) => (
                    <tr key={r.id} className={cn('border-b border-border/30', i % 2 === 0 ? '' : 'bg-muted/20')}>
                      <td className="px-4 py-2.5 font-mono text-muted-foreground">#{r.domain_id}</td>
                      <td className="px-4 py-2.5">
                        <span className={cn('rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold',
                          r.tls_version === 'TLSv1.3' ? 'bg-emerald-500/10 text-emerald-600' :
                          r.tls_version === 'TLSv1.2' ? 'bg-yellow-500/10 text-yellow-600' :
                          'bg-red-500/10 text-red-600'
                        )}>
                          {r.tls_version ?? '—'}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[10px] text-muted-foreground max-w-[180px] truncate">
                        {r.cipher_suite ?? '—'}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[10px] text-muted-foreground">
                        {r.key_exchange ?? '—'}
                      </td>
                      <td className="px-4 py-2.5">
                        {r.supports_pqc
                          ? <CheckCircle2 size={14} className="text-emerald-500" />
                          : <XCircle size={14} className="text-muted-foreground/40" />}
                      </td>
                      <td className="px-4 py-2.5">
                        {r.flag_legacy_tls
                          ? <span className="rounded px-1.5 py-0.5 bg-red-500/10 text-red-600 font-mono text-[10px]">Yes</span>
                          : <span className="font-mono text-[10px] text-muted-foreground">No</span>}
                      </td>
                      <td className="px-4 py-2.5">
                        <span className={cn('font-mono text-xs font-semibold', scoreColor(r.security_score ?? 0))}>
                          {r.security_score != null ? Math.round(r.security_score) : '—'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── Vulnerabilities Table ──────────────────────────────────────── */}
        {vulns.length > 0 && (
          <div className="rounded-xl border border-border bg-card">
            <div className="border-b border-border px-5 py-4">
              <h2 className="text-sm font-semibold text-foreground">Detected Vulnerabilities</h2>
              <p className="text-[11px] text-muted-foreground">{vulns.length} vulnerability record{vulns.length !== 1 ? 's' : ''} found</p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border/50">
                    {['Severity', 'CVE ID', 'CVSS', 'Description'].map(h => (
                      <th key={h} className="px-4 py-2.5 text-left font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {vulns.map((v, i) => (
                    <tr key={v.id} className={cn('border-b border-border/30', i % 2 === 0 ? '' : 'bg-muted/20')}>
                      <td className="px-4 py-2.5">
                        <span className={cn('rounded px-2 py-0.5 text-[10px] font-semibold font-mono', severityColor(v.severity))}>
                          {v.severity}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[10px] text-muted-foreground">
                        {v.cve_id ?? '—'}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[10px]">
                        {v.cvss_score != null
                          ? <span className={cn('font-semibold',
                              v.cvss_score >= 9 ? 'text-red-600' :
                              v.cvss_score >= 7 ? 'text-orange-500' :
                              v.cvss_score >= 4 ? 'text-yellow-500' : 'text-emerald-500'
                            )}>{v.cvss_score.toFixed(1)}</span>
                          : <span className="text-muted-foreground">—</span>}
                      </td>
                      <td className="px-4 py-2.5 text-[11px] text-foreground max-w-[280px]">
                        {v.description}
                        {v.reference_url && (
                          <a href={v.reference_url} target="_blank" rel="noreferrer"
                            className="ml-1.5 font-mono text-[10px] text-primary underline no-print">
                            ref
                          </a>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── Domains ───────────────────────────────────────────────────── */}
        {domains.length > 0 && (
          <div className="rounded-xl border border-border bg-card">
            <div className="border-b border-border px-5 py-4">
              <h2 className="text-sm font-semibold text-foreground">Domain Inventory</h2>
              <p className="text-[11px] text-muted-foreground">{domains.length} domain{domains.length !== 1 ? 's' : ''} discovered</p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border/50">
                    {['Domain', 'IP Address', 'Country', 'Class', 'Third-party'].map(h => (
                      <th key={h} className="px-4 py-2.5 text-left font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {domains.map((d, i) => (
                    <tr key={d.id} className={cn('border-b border-border/30', i % 2 === 0 ? '' : 'bg-muted/20')}>
                      <td className="px-4 py-2.5 font-mono text-[11px] text-foreground">{d.domain}</td>
                      <td className="px-4 py-2.5 font-mono text-[10px] text-muted-foreground">{d.ip ?? '—'}</td>
                      <td className="px-4 py-2.5 font-mono text-[10px] text-muted-foreground">{d.country ?? '—'}</td>
                      <td className="px-4 py-2.5 font-mono text-[10px] text-muted-foreground">{d.domain_class ?? '—'}</td>
                      <td className="px-4 py-2.5">
                        {d.is_third_party
                          ? <span className="rounded px-1.5 py-0.5 bg-amber-500/10 text-amber-600 font-mono text-[10px]">Yes</span>
                          : <span className="font-mono text-[10px] text-muted-foreground">No</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── ML Prediction ─────────────────────────────────────────────── */}
        {prediction && (
          <div className="rounded-xl border border-border bg-card p-5">
            <div className="mb-4 flex items-center gap-2">
              <Cpu size={16} className="text-primary" />
              <h2 className="text-sm font-semibold text-foreground">ML Risk Prediction</h2>
            </div>
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              {[
                { label: 'Predicted Score', value: Math.round(prediction.security_score) },
                { label: 'Risk Level', value: prediction.risk_level },
                { label: 'PQC Readiness', value: `${Math.round(prediction.pqc_readiness_score)}%` },
                { label: 'Confidence', value: prediction.confidence != null ? `${(prediction.confidence * 100).toFixed(1)}%` : '—' },
              ].map(({ label, value }) => (
                <div key={label} className="rounded-lg border border-border/60 p-3">
                  <p className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">{label}</p>
                  <p className="mt-1 font-mono text-lg font-bold text-foreground">{value}</p>
                </div>
              ))}
            </div>
            {prediction.feature_importances && Object.keys(prediction.feature_importances).length > 0 && (
              <div className="mt-4">
                <p className="mb-2 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Feature Importances</p>
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                  {Object.entries(prediction.feature_importances)
                    .sort(([, a], [, b]) => b - a)
                    .slice(0, 6)
                    .map(([feat, imp]) => (
                      <div key={feat} className="flex items-center gap-2">
                        <div className="h-1.5 rounded-full bg-primary/20 flex-1">
                          <div className="h-1.5 rounded-full bg-primary" style={{ width: `${Math.min(imp * 100, 100)}%` }} />
                        </div>
                        <span className="font-mono text-[10px] text-muted-foreground w-8 text-right">
                          {(imp * 100).toFixed(0)}%
                        </span>
                        <span className="font-mono text-[10px] text-foreground truncate max-w-[80px]">{feat}</span>
                      </div>
                    ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Security Flags Summary ─────────────────────────────────────── */}
        {tlsResults.length > 0 && (
          <div className="rounded-xl border border-border bg-card p-5">
            <div className="mb-4 flex items-center gap-2">
              <Server size={16} className="text-primary" />
              <h2 className="text-sm font-semibold text-foreground">Security Flags Summary</h2>
            </div>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              {[
                { label: 'Legacy TLS Detected', value: legacyCount, bad: legacyCount > 0 },
                { label: 'PQC-Enabled Domains', value: pqcDomains, bad: pqcDomains === 0 },
                { label: 'RSA Key Exchange', value: tlsResults.filter(r => r.has_rsa_key_exchange).length, bad: true },
                { label: 'RC4 / 3DES Ciphers', value: tlsResults.filter(r => r.flag_rc4_or_3des).length, bad: true },
              ].map(({ label, value, bad }) => (
                <div key={label} className={cn(
                  'rounded-lg border p-3',
                  value > 0 && bad ? 'border-red-200 bg-red-500/5' :
                  value === 0 && !bad ? 'border-red-200 bg-red-500/5' :
                  'border-emerald-200 bg-emerald-500/5'
                )}>
                  <p className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">{label}</p>
                  <p className={cn('mt-1 font-mono text-xl font-bold',
                    (value > 0 && bad) || (value === 0 && !bad) ? 'text-red-600' : 'text-emerald-600'
                  )}>
                    {value}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Footer ────────────────────────────────────────────────────── */}
        <div className="flex items-center justify-between border-t border-border pt-4 text-[10px] font-mono text-muted-foreground">
          <span>QuantumShield 2.0 — TLS &amp; PQC Analysis Report</span>
          <span>Generated {new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</span>
        </div>
      </div>
    </div>
  )
}
