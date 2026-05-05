import React, { useState, useRef, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { ScanSearch, Upload, CheckCircle2, ChevronRight, AlertCircle, Globe, Shield, Award, FileBarChart2, Link2, Package } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Progress } from '../components/ui/progress'
import { Separator } from '../components/ui/separator'
import { cn, scoreColor, riskVariant } from '../lib/utils'
import { appsApi, ApiError } from '../lib/api'
import type { MLPredictionOut, VulnerabilityOut, DomainOut, TLSResultOut, WarrantyOut } from '../lib/api'
import type { RiskLevel } from '../lib/types'

type InputMode = 'package' | 'url' | 'apk'

const ANALYSIS_STEPS = [
  'Uploading package…',
  'Queuing scan pipeline…',
  'Running TLS analysis…',
  'Running PQC analysis…',
  'Generating ML prediction…',
]

interface AnalysisResults {
  appId: number
  score: number
  risk: RiskLevel
  pqcScore: number
  pqc: boolean
  vulns: { severity: string; label: string; count: number }[]
  recommendations: string[]
}

// ── Score ring ────────────────────────────────────────────────────────────────
const ScoreRing: React.FC<{ score: number; size?: number }> = ({ score, size = 96 }) => {
  const r = (size - 10) / 2
  const circ = 2 * Math.PI * r
  const offset = circ - (score / 100) * circ
  const color = score >= 90 ? '#22c55e' : score >= 75 ? '#84cc16' : score >= 60 ? '#f59e0b' : '#ef4444'
  return (
    <svg width={size} height={size} className="-rotate-90">
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="hsl(var(--muted))" strokeWidth={8} />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={8}
        strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
        style={{ transition: 'stroke-dashoffset 0.8s ease' }} />
    </svg>
  )
}

function buildRecommendations(pred: MLPredictionOut, vulns: VulnerabilityOut[]): string[] {
  const recs: string[] = []
  if (pred.pqc_readiness_score < 50) {
    recs.push('Migrate to NIST-approved post-quantum key exchange algorithms (e.g., ML-KEM, ML-DSA).')
  }
  if (vulns.some(v => v.severity === 'High' || v.severity === 'Critical')) {
    recs.push('Address high-severity vulnerabilities immediately to reduce attack surface.')
  }
  if (pred.security_score < 70) {
    recs.push('Upgrade TLS to version 1.3 and disable legacy cipher suites.')
  }
  if (vulns.some(v => v.description.toLowerCase().includes('certificate'))) {
    recs.push('Implement certificate pinning to prevent MITM attacks.')
  }
  if (recs.length === 0) {
    recs.push('Continue monitoring — your application meets current security standards.')
  }
  return recs
}

// ── TLS version badge colour ──────────────────────────────────────────────────
function tlsVariant(ver: string | null) {
  if (!ver) return 'outline' as const
  if (ver === 'TLSv1.3' || ver === '1.3') return 'success' as const
  if (ver === 'TLSv1.2' || ver === '1.2') return 'secondary' as const
  return 'destructive' as const
}

// ── Warranty badge ────────────────────────────────────────────────────────────
function warrantyVariant(status: string) {
  if (status === 'Certified') return 'success' as const
  if (status === 'Conditional') return 'warning' as const
  return 'destructive' as const
}

export const AnalyzeAppPage: React.FC = () => {
  const navigate = useNavigate()
  const [mode, setMode] = useState<InputMode>('package')
  const [pkg, setPkg] = useState('')
  const [urlInput, setUrlInput] = useState('')
  const [fileName, setFileName] = useState<string | null>(null)
  const [fileObj, setFileObj] = useState<File | null>(null)
  const [dragOver, setDragOver] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [step, setStep] = useState(0)
  const [results, setResults] = useState<AnalysisResults | null>(null)
  const [domains, setDomains] = useState<DomainOut[]>([])
  const [tlsResults, setTlsResults] = useState<TLSResultOut[]>([])
  const [warranty, setWarranty] = useState<WarrantyOut | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [publicPrompt, setPublicPrompt] = useState<{ appId: number; appName: string } | null>(null)
  const [publicStatus, setPublicStatus] = useState<'idle' | 'done'>('idle')
  const fileInputRef = useRef<HTMLInputElement>(null)
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => () => { if (pollRef.current) clearTimeout(pollRef.current) }, [])

  const canAnalyze = (
    (mode === 'package' && pkg.trim().length > 0) ||
    (mode === 'url' && urlInput.trim().length > 0) ||
    (mode === 'apk' && fileName !== null)
  ) && !analyzing

  const handleFile = (file: File) => {
    if (file.name.endsWith('.apk')) {
      setFileName(file.name)
      setFileObj(file)
    }
  }

  const pollForResults = useCallback((appId: number, attempt = 0) => {
    setStep(3)
    appsApi.get(appId).then(async app => {
      // ── FIX: backend sets 'completed', not 'complete' ──────────────────
      if (app.scan_status === 'completed') {
        setStep(4)
        try {
          const [pred, vulns, doms, tls, warr] = await Promise.all([
            appsApi.prediction(appId),
            appsApi.vulnerabilities(appId),
            appsApi.domains(appId),
            appsApi.tls(appId),
            appsApi.warranty(appId).catch(() => null),   // warranty may not exist
          ])
          setStep(5)

          // Group vulns by severity
          const grouped: Record<string, number> = {}
          vulns.forEach(v => { grouped[v.severity] = (grouped[v.severity] ?? 0) + 1 })
          const vulnList = Object.entries(grouped).map(([severity, count]) => ({
            severity,
            label: vulns.find(v => v.severity === severity)?.description ?? `${severity} severity issue`,
            count,
          }))

          const appInfo = await appsApi.get(appId).catch(() => null)
          setResults({
            appId,
            score: Math.round(pred.security_score),
            risk: pred.risk_level as RiskLevel,
            pqcScore: Math.round(pred.pqc_readiness_score),
            pqc: pred.pqc_readiness_score > 50,
            vulns: vulnList,
            recommendations: buildRecommendations(pred, vulns),
          })
          setDomains(doms)
          setTlsResults(tls)
          setWarranty(warr)
          setPublicPrompt({ appId, appName: appInfo?.app_name ?? appInfo?.package_name ?? `App #${appId}` })
          setPublicStatus('idle')
        } catch {
          setError('Analysis complete but failed to fetch results. Try again.')
        }
        setAnalyzing(false)
      } else if (app.scan_status === 'failed') {
        setError('Scan failed. The application could not be analyzed.')
        setAnalyzing(false)
      } else if (attempt < 60) {
        pollRef.current = setTimeout(() => pollForResults(appId, attempt + 1), 3000)
      } else {
        setError('Scan timed out. Please try again later.')
        setAnalyzing(false)
      }
    }).catch(() => {
      if (attempt < 60) {
        pollRef.current = setTimeout(() => pollForResults(appId, attempt + 1), 3000)
      } else {
        setError('Failed to check scan status.')
        setAnalyzing(false)
      }
    })
  }, [])

  const startAnalysis = async () => {
    setAnalyzing(true)
    setResults(null)
    setDomains([])
    setTlsResults([])
    setWarranty(null)
    setError(null)
    setStep(1)

    try {
      let app
      if (mode === 'apk' && fileObj) {
        app = await appsApi.uploadApk(fileObj, undefined, undefined)
      } else if (mode === 'url') {
        app = await appsApi.analyzeUrl(urlInput.trim())
      } else {
        app = await appsApi.submit(pkg.trim())
      }
      setStep(2)
      pollForResults(app.id)
    } catch (err) {
      setAnalyzing(false)
      if (err instanceof ApiError) {
        if (err.status === 403) {
          setError('You need "App Owner" or "Admin" role to submit apps for analysis.')
        } else {
          setError(err.message)
        }
      } else {
        setError('Failed to submit application. Is the backend running?')
      }
    }
  }

  const reset = () => {
    if (pollRef.current) clearTimeout(pollRef.current)
    setPkg('')
    setUrlInput('')
    setFileName(null)
    setFileObj(null)
    setResults(null)
    setDomains([])
    setTlsResults([])
    setWarranty(null)
    setStep(0)
    setError(null)
    setAnalyzing(false)
    setPublicPrompt(null)
    setPublicStatus('idle')
  }

  const handleMakePublic = async (appId: number) => {
    try { await appsApi.setVisibility(appId, true) } catch { /* ignore */ }
    setPublicPrompt(null)
    setPublicStatus('done')
  }

  // Build domain→TLS lookup
  const tlsByDomainId = Object.fromEntries(tlsResults.map(t => [t.domain_id, t]))

  return (
    <div className="flex flex-col gap-5 p-6">
      {/* Input card */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-semibold">Submit Application</CardTitle>
          <CardDescription className="text-xs">Analyze by package name, URL / domain, or APK upload</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">

          {/* Mode tabs */}
          <div className="flex gap-1 rounded-lg border border-border bg-muted/30 p-1">
            {([
              { id: 'package', label: 'Package Name', icon: Package },
              { id: 'url',     label: 'URL / Domain', icon: Link2 },
              { id: 'apk',     label: 'APK Upload',   icon: Upload },
            ] as { id: InputMode; label: string; icon: React.FC<{ size?: number; className?: string }> }[]).map(tab => (
              <button
                key={tab.id}
                type="button"
                disabled={analyzing}
                onClick={() => { setMode(tab.id); setError(null) }}
                className={cn(
                  'flex flex-1 items-center justify-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
                  mode === tab.id
                    ? 'bg-background text-foreground shadow-sm'
                    : 'text-muted-foreground hover:text-foreground',
                )}
              >
                <tab.icon size={12} />
                {tab.label}
              </button>
            ))}
          </div>

          {/* Package Name */}
          {mode === 'package' && (
            <div>
              <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                Android Package Name
              </label>
              <Input
                placeholder="com.example.application"
                value={pkg}
                onChange={e => setPkg(e.target.value)}
                className="font-mono text-xs"
                disabled={analyzing}
              />
            </div>
          )}

          {/* URL / Domain */}
          {mode === 'url' && (
            <div className="flex flex-col gap-2">
              <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                URL or Domain
              </label>
              <Input
                placeholder="https://example.com  ·  api.company.io  ·  play.google.com/…?id=com.app"
                value={urlInput}
                onChange={e => setUrlInput(e.target.value)}
                className="font-mono text-xs"
                disabled={analyzing}
              />
              <p className="font-mono text-[10px] text-muted-foreground/60">
                Accepts: full URLs, bare domains, or Google Play Store links
              </p>
            </div>
          )}

          {/* APK Upload */}
          {mode === 'apk' && (
            <div
              className={cn(
                'relative flex flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed py-8 transition-colors',
                dragOver ? 'border-foreground/40 bg-muted/30' : 'border-border',
                fileName ? 'border-emerald-500/40 bg-emerald-500/5' : '',
              )}
              onDragOver={e => { e.preventDefault(); setDragOver(true) }}
              onDragLeave={() => setDragOver(false)}
              onDrop={e => {
                e.preventDefault()
                setDragOver(false)
                const file = e.dataTransfer.files[0]
                if (file) handleFile(file)
              }}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".apk"
                className="hidden"
                onChange={e => { const f = e.target.files?.[0]; if (f) handleFile(f) }}
              />
              {fileName ? (
                <>
                  <CheckCircle2 size={20} className="text-emerald-500" />
                  <p className="text-xs font-medium text-foreground">{fileName}</p>
                  <button type="button" onClick={() => { setFileName(null); setFileObj(null) }}
                    className="font-mono text-[10px] text-muted-foreground/50 hover:text-muted-foreground">
                    Remove
                  </button>
                </>
              ) : (
                <>
                  <Upload size={20} className="text-muted-foreground/40" />
                  <p className="text-xs text-muted-foreground">Drag & drop an APK file, or</p>
                  <Button variant="outline" size="sm" className="h-7 text-xs"
                    onClick={() => fileInputRef.current?.click()} disabled={analyzing}>
                    Browse files
                  </Button>
                  <p className="font-mono text-[10px] text-muted-foreground/40">.apk files only</p>
                </>
              )}
            </div>
          )}

          {error && (
            <div className="flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2.5">
              <AlertCircle size={14} className="mt-0.5 shrink-0 text-destructive" />
              <p className="text-xs text-destructive">{error}</p>
            </div>
          )}

          <Button onClick={startAnalysis} disabled={!canAnalyze} className="gap-2">
            <ScanSearch size={14} />
            Analyze
          </Button>
        </CardContent>
      </Card>

      {/* Progress */}
      {analyzing && (
        <Card>
          <CardContent className="py-6">
            <div className="flex flex-col gap-4">
              <div className="flex items-center justify-between">
                <p className="text-sm font-medium text-foreground">Analyzing…</p>
                <span className="font-mono text-[11px] text-muted-foreground">{Math.min(step, ANALYSIS_STEPS.length)} / {ANALYSIS_STEPS.length}</span>
              </div>
              <Progress value={(Math.min(step, ANALYSIS_STEPS.length) / ANALYSIS_STEPS.length) * 100} className="h-1.5" />
              <div className="flex flex-col gap-1.5">
                {ANALYSIS_STEPS.map((s, i) => (
                  <div key={s} className={cn('flex items-center gap-2 text-xs transition-colors', i < step ? 'text-foreground' : 'text-muted-foreground/30')}>
                    {i < step
                      ? <CheckCircle2 size={12} className="text-emerald-500 shrink-0" />
                      : i === step
                        ? <span aria-hidden="true" className="h-3 w-3 shrink-0 animate-spin rounded-full border-2 border-current border-t-transparent" />
                        : <span className="h-3 w-3 shrink-0 rounded-full border border-current" />}
                    {s}
                  </div>
                ))}
              </div>
              <p className="font-mono text-[10px] text-muted-foreground/50">
                Scanning may take 30–90 seconds depending on the app.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Results */}
      {results && (
        <div className="flex flex-col gap-4">

          {/* Add-to-public-database prompt */}
          {publicPrompt && publicStatus === 'idle' && (
            <Card className="border-primary/30 bg-primary/5">
              <CardContent className="flex flex-col gap-3 py-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <p className="text-sm font-medium text-foreground">
                    Would you like to add <span className="font-semibold">{publicPrompt.appName}</span> to the public database?
                  </p>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    Other users will be able to view the analysis results in the Browse Apps page.
                  </p>
                </div>
                <div className="flex shrink-0 gap-2">
                  <Button size="sm" className="h-8 text-xs gap-1.5" onClick={() => handleMakePublic(publicPrompt.appId)}>
                    Yes, make public
                  </Button>
                  <Button variant="outline" size="sm" className="h-8 text-xs" onClick={() => setPublicPrompt(null)}>
                    Keep private
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
          {publicStatus === 'done' && (
            <div className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-4 py-2.5 text-xs text-emerald-600 dark:text-emerald-400">
              <CheckCircle2 size={13} /> Added to the public database.
            </div>
          )}

          {/* Row 1: Score + Vulnerabilities */}
          <div className="grid gap-4 sm:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="text-sm font-semibold">Security Score</CardTitle>
              </CardHeader>
              <CardContent className="flex items-center gap-5">
                <div className="relative flex h-24 w-24 shrink-0 items-center justify-center">
                  <ScoreRing score={results.score} size={96} />
                  <span className={cn('absolute font-mono text-xl font-bold', scoreColor(results.score))}>
                    {results.score}
                  </span>
                </div>
                <div className="flex flex-col gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Risk</span>
                    <Badge variant={riskVariant(results.risk)}>{results.risk}</Badge>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">PQC Score</span>
                    <span className="font-mono text-xs font-semibold text-foreground">{results.pqcScore}%</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">PQC Ready</span>
                    <Badge variant={results.pqc ? 'success' as const : 'destructive'}>{results.pqc ? 'Ready' : 'Not Ready'}</Badge>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-sm font-semibold">Vulnerabilities</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col gap-2">
                {results.vulns.length === 0 ? (
                  <p className="text-xs text-muted-foreground">No vulnerabilities detected.</p>
                ) : results.vulns.map(v => (
                  <div key={v.severity} className="flex items-center justify-between rounded-md border border-border/50 px-3 py-2">
                    <div className="flex items-center gap-2">
                      <span className={cn('h-2 w-2 rounded-full shrink-0',
                        v.severity === 'High' || v.severity === 'Critical' ? 'bg-destructive'
                        : v.severity === 'Medium' ? 'bg-amber-500' : 'bg-emerald-500'
                      )} />
                      <span className="text-xs text-foreground capitalize">{v.severity} severity</span>
                    </div>
                    <span className="font-mono text-xs font-bold text-muted-foreground">{v.count}</span>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>

          {/* Row 2: Domains & TLS */}
          {domains.length > 0 && (
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Globe size={14} className="text-muted-foreground" />
                  <div>
                    <CardTitle className="text-sm font-semibold">Domains & TLS Analysis</CardTitle>
                    <CardDescription className="text-xs">{domains.length} domain{domains.length !== 1 ? 's' : ''} discovered</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="p-0">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-border">
                      {['Domain', 'IP', 'Country', 'TLS', 'PQC', 'Cipher Score', 'Quantum Risk'].map(h => (
                        <th key={h} className="bg-muted/30 px-3 py-2 text-left font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {domains.map(dom => {
                      const tls = tlsByDomainId[dom.id]
                      return (
                        <tr key={dom.id} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                          <td className="px-3 py-2.5 font-mono font-medium text-foreground max-w-[180px]">
                            <div className="truncate" title={dom.domain}>{dom.domain}</div>
                            {dom.is_third_party && (
                              <span className="text-[9px] text-muted-foreground">3rd party</span>
                            )}
                          </td>
                          <td className="px-3 py-2.5 font-mono text-muted-foreground">{dom.ip ?? '—'}</td>
                          <td className="px-3 py-2.5 text-muted-foreground">{dom.country ?? '—'}</td>
                          <td className="px-3 py-2.5">
                            {tls?.tls_version
                              ? <Badge variant={tlsVariant(tls.tls_version)} className="font-mono text-[10px]">{tls.tls_version}</Badge>
                              : <span className="text-muted-foreground">—</span>}
                          </td>
                          <td className="px-3 py-2.5">
                            {tls
                              ? <Badge variant={tls.supports_pqc ? 'success' as const : 'outline'}>{tls.supports_pqc ? 'Yes' : 'No'}</Badge>
                              : <span className="text-muted-foreground">—</span>}
                          </td>
                          <td className="px-3 py-2.5 font-mono text-muted-foreground">
                            {tls?.cipher_strength_score != null ? tls.cipher_strength_score.toFixed(1) : '—'}
                          </td>
                          <td className="px-3 py-2.5 font-mono">
                            {tls?.quantum_risk_score != null ? (
                              <span className={tls.quantum_risk_score > 0.6 ? 'text-destructive' : tls.quantum_risk_score > 0.3 ? 'text-amber-500' : 'text-emerald-500'}>
                                {(tls.quantum_risk_score * 100).toFixed(0)}%
                              </span>
                            ) : '—'}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </CardContent>
            </Card>
          )}

          {/* Row 3: Security Warranty */}
          {warranty && (
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Award size={14} className="text-muted-foreground" />
                  <div>
                    <CardTitle className="text-sm font-semibold">Security Warranty</CardTitle>
                    <CardDescription className="text-xs">Certification status based on PQC readiness and security posture</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <Separator />
              <CardContent className="pt-4">
                <div className="flex flex-col gap-3">
                  <div className="flex items-center gap-3">
                    <Badge variant={warrantyVariant(warranty.status)} className="text-sm px-3 py-1">
                      <Shield size={12} className="mr-1.5" />
                      {warranty.status}
                    </Badge>
                  </div>
                  {warranty.justification && (
                    <p className="text-xs text-muted-foreground leading-relaxed">{warranty.justification}</p>
                  )}
                  <div className="flex flex-wrap gap-4 text-[10px] font-mono text-muted-foreground">
                    <span>Issued: {new Date(warranty.issued_at).toLocaleDateString()}</span>
                    {warranty.expires_at && (
                      <span>Expires: {new Date(warranty.expires_at).toLocaleDateString()}</span>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Row 4: Recommendations */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-semibold">Recommendations</CardTitle>
              <CardDescription className="text-xs">Actions to improve your application's security posture</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-2">
              {results.recommendations.map((rec, i) => (
                <div key={i} className="flex items-start gap-2.5 rounded-md bg-muted/30 px-3 py-2.5">
                  <ChevronRight size={13} className="mt-0.5 shrink-0 text-primary" />
                  <p className="text-xs text-foreground">{rec}</p>
                </div>
              ))}
            </CardContent>
          </Card>

          <div className="flex gap-2">
            <Button variant="outline" size="sm" className="gap-1.5" onClick={reset}>
              <ScanSearch size={12} /> Analyze Another
            </Button>
            <Button
              variant="outline" size="sm" className="gap-1.5"
              onClick={() => navigate(`/apps/${results.appId}/report`)}
            >
              <FileBarChart2 size={12} /> View Report
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
