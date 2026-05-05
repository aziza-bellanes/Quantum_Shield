import React, { useState, useEffect } from 'react'
import { Check, X, Globe, Shield, AlertTriangle, Award, ChevronDown, ChevronUp, Package, Star } from 'lucide-react'
import { Badge } from './ui/badge'
import { Progress } from './ui/progress'
import { Separator } from './ui/separator'
import {
  Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription,
} from './ui/sheet'
import { appsApi } from '../lib/api'
import type { AppOut, DomainOut, TLSResultOut, VulnerabilityOut, MLPredictionOut, WarrantyOut } from '../lib/api'
import { scoreColor, scoreBarColor, riskVariant, cn } from '../lib/utils'
import type { RiskLevel } from '../lib/types'

function sevDot(sev: string) {
  if (sev === 'Critical' || sev === 'High') return 'bg-destructive'
  if (sev === 'Medium') return 'bg-amber-500'
  return 'bg-emerald-500'
}

export const AppDetailSheet: React.FC<{ app: AppOut | null; open: boolean; onClose: () => void }> = ({ app, open, onClose }) => {
  const [detail, setDetail] = useState({
    loading: true,
    domains:    [] as DomainOut[],
    tls:        [] as TLSResultOut[],
    vulns:      [] as VulnerabilityOut[],
    prediction: null as MLPredictionOut | null,
    warranty:   null as WarrantyOut | null,
  })
  const [tlsExpanded, setTlsExpanded] = useState(true)
  const [vulnsExpanded, setVulnsExpanded] = useState(true)

  useEffect(() => {
    if (!app || !open) return
    let active = true
    setDetail(d => ({ ...d, loading: true }))
    Promise.all([
      appsApi.domains(app.id).catch(() => [] as DomainOut[]),
      appsApi.tls(app.id).catch(() => [] as TLSResultOut[]),
      appsApi.vulnerabilities(app.id).catch(() => [] as VulnerabilityOut[]),
      appsApi.prediction(app.id).catch(() => null as MLPredictionOut | null),
      appsApi.warranty(app.id).catch(() => null as WarrantyOut | null),
    ]).then(([doms, tlsRes, vulnRes, pred, warr]) => {
      if (!active) return
      setDetail({ loading: false, domains: doms, tls: tlsRes, vulns: vulnRes, prediction: pred, warranty: warr })
    })
    return () => { active = false }
  }, [app, open])

  const { loading, domains, tls, vulns, prediction, warranty } = detail

  if (!app) return null

  const score = Math.round(app.security_score ?? prediction?.security_score ?? 0)
  const risk = (app.risk_level ?? prediction?.risk_level ?? 'Medium') as RiskLevel
  const pqc = (app.pqc_readiness_score ?? prediction?.pqc_readiness_score ?? 0) > 50
  const pqcScore = Math.round(app.pqc_readiness_score ?? prediction?.pqc_readiness_score ?? 0)
  const tlsById = Object.fromEntries(tls.map(t => [t.domain_id, t]))

  const vulnGroups: Record<string, number> = {}
  vulns.forEach(v => { vulnGroups[v.severity] = (vulnGroups[v.severity] ?? 0) + 1 })

  const warrantyVariant = (s: string) =>
    s === 'Certified' ? 'success' as const : s === 'Conditional' ? 'warning' as const : 'destructive' as const

  return (
    <Sheet open={open} onOpenChange={v => { if (!v) onClose() }}>
      <SheetContent side="right" className="w-full sm:max-w-xl flex flex-col p-0 overflow-hidden">

        <SheetHeader className="shrink-0 px-5 pt-5 pb-3">
          <div className="flex items-start gap-3">
            <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-muted">
              <Package size={20} className="text-muted-foreground" />
            </div>
            <div className="min-w-0 flex-1 pr-8">
              <SheetTitle className="truncate text-base">{app.app_name ?? app.package_name}</SheetTitle>
              <SheetDescription className="truncate font-mono text-[10px]">{app.package_name}</SheetDescription>
              <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                {app.category && <Badge variant="secondary">{app.category}</Badge>}
                {app.install_count != null && (
                  <span className="font-mono text-[10px] text-muted-foreground">{app.install_count.toLocaleString()} installs</span>
                )}
                {app.rating != null && (
                  <span className="flex items-center gap-1 font-mono text-[10px] text-muted-foreground">
                    <Star size={10} className="fill-amber-400 text-amber-400" /> {app.rating.toFixed(1)}
                  </span>
                )}
              </div>
            </div>
          </div>
        </SheetHeader>
        <Separator />

        <div className="flex-1 overflow-y-auto">
          {loading ? (
            <div className="flex items-center justify-center py-20">
              <span role="status" aria-label="Loading"
                className="h-5 w-5 animate-spin rounded-full border-2 border-foreground border-t-transparent" />
            </div>
          ) : (
            <div className="flex flex-col gap-0 divide-y divide-border/40">

              {app.description && (
                <div className="px-5 py-4">
                  <p className="text-xs leading-relaxed text-muted-foreground">{app.description}</p>
                </div>
              )}

              {(score > 0 || prediction !== null || app.security_score !== null) && (
                <div className="px-5 py-4">
                  <p className="mb-3 font-mono text-[9px] uppercase tracking-widest text-muted-foreground">Security Overview</p>
                  <div className="flex items-center gap-4 mb-3">
                    <div className="relative shrink-0">
                      <svg width="72" height="72" className="-rotate-90">
                        <circle cx="36" cy="36" r="28" fill="none" stroke="hsl(var(--muted))" strokeWidth="6" />
                        <circle cx="36" cy="36" r="28" fill="none"
                          stroke={score >= 90 ? '#22c55e' : score >= 75 ? '#84cc16' : score >= 60 ? '#f59e0b' : '#ef4444'}
                          strokeWidth="6"
                          strokeDasharray={2 * Math.PI * 28}
                          strokeDashoffset={2 * Math.PI * 28 * (1 - score / 100)}
                          strokeLinecap="round"
                          style={{ transition: 'stroke-dashoffset 0.6s ease' }}
                        />
                      </svg>
                      <span className={cn('absolute inset-0 flex items-center justify-center font-mono text-lg font-bold', scoreColor(score))}>
                        {score}
                      </span>
                    </div>
                    <div className="flex flex-col gap-2 flex-1">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">Risk</span>
                        <Badge variant={riskVariant(risk)}>{risk}</Badge>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">PQC Ready</span>
                        {pqc
                          ? <span className="flex items-center gap-1 font-mono text-[11px] font-semibold text-emerald-500"><Check size={11} /> Yes</span>
                          : <span className="flex items-center gap-1 font-mono text-[11px] font-semibold text-destructive"><X size={10} /> No</span>}
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">PQC Score</span>
                        <span className="font-mono text-xs font-semibold">{pqcScore}%</span>
                      </div>
                      {prediction?.confidence != null && (
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">ML Confidence</span>
                          <span className="font-mono text-xs font-semibold">{Math.round(prediction.confidence * 100)}%</span>
                        </div>
                      )}
                    </div>
                  </div>
                  <Progress value={score} indicatorClassName={scoreBarColor(score)} className="h-1.5" />
                </div>
              )}

              <div className="px-5 py-4">
                <button className="flex w-full items-center justify-between" onClick={() => setVulnsExpanded(v => !v)}>
                  <div className="flex items-center gap-2">
                    <AlertTriangle size={13} className="text-muted-foreground" />
                    <span className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">Vulnerabilities</span>
                    {vulns.length > 0 && (
                      <Badge variant="destructive" className="h-4 px-1.5 font-mono text-[9px]">{vulns.length}</Badge>
                    )}
                  </div>
                  {vulnsExpanded ? <ChevronUp size={13} className="text-muted-foreground" /> : <ChevronDown size={13} className="text-muted-foreground" />}
                </button>
                {vulnsExpanded && (
                  <div className="mt-3">
                    {vulns.length === 0 ? (
                      <p className="text-xs text-muted-foreground">No vulnerabilities detected.</p>
                    ) : (
                      <div className="flex flex-col gap-1.5">
                        <div className="flex flex-wrap gap-2 mb-2">
                          {Object.entries(vulnGroups).map(([sev, cnt]) => (
                            <div key={sev} className="flex items-center gap-1.5 rounded-md border border-border/50 px-2.5 py-1">
                              <span className={cn('h-2 w-2 rounded-full shrink-0', sevDot(sev))} />
                              <span className="text-xs text-foreground">{sev}</span>
                              <span className="font-mono text-xs font-bold text-muted-foreground">{cnt}</span>
                            </div>
                          ))}
                        </div>
                        {vulns.slice(0, 5).map(v => (
                          <div key={v.id} className="flex items-start gap-2 rounded-md bg-muted/20 px-3 py-2">
                            <span className={cn('mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full', sevDot(v.severity))} />
                            <div className="min-w-0">
                              <p className="text-[11px] text-foreground leading-snug">{v.description}</p>
                              {v.cve_id && <p className="font-mono text-[9px] text-muted-foreground">{v.cve_id}</p>}
                            </div>
                          </div>
                        ))}
                        {vulns.length > 5 && (
                          <p className="font-mono text-[10px] text-muted-foreground text-center">+{vulns.length - 5} more</p>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {warranty && (
                <div className="px-5 py-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Award size={13} className="text-muted-foreground" />
                    <span className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">Security Warranty</span>
                  </div>
                  <div className="flex flex-col gap-2">
                    <Badge variant={warrantyVariant(warranty.status)} className="w-fit px-3 py-1 text-xs">
                      <Shield size={11} className="mr-1.5" />{warranty.status}
                    </Badge>
                    {warranty.justification && (
                      <p className="text-[11px] leading-relaxed text-muted-foreground">{warranty.justification}</p>
                    )}
                    <div className="flex gap-4 font-mono text-[10px] text-muted-foreground">
                      <span>Issued: {new Date(warranty.issued_at).toLocaleDateString()}</span>
                      {warranty.expires_at && <span>Expires: {new Date(warranty.expires_at).toLocaleDateString()}</span>}
                    </div>
                  </div>
                </div>
              )}

              <div className="px-5 py-4">
                <button className="flex w-full items-center justify-between" onClick={() => setTlsExpanded(v => !v)}>
                  <div className="flex items-center gap-2">
                    <Globe size={13} className="text-muted-foreground" />
                    <span className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">Domains & TLS</span>
                    <span className="font-mono text-[9px] text-muted-foreground/60">({domains.length})</span>
                  </div>
                  {tlsExpanded ? <ChevronUp size={13} className="text-muted-foreground" /> : <ChevronDown size={13} className="text-muted-foreground" />}
                </button>
                {tlsExpanded && (
                  <div className="mt-3 flex flex-col gap-2">
                    {domains.length === 0 ? (
                      <p className="text-xs text-muted-foreground">No domain data available.</p>
                    ) : domains.map(dom => {
                      const t = tlsById[dom.id]
                      return (
                        <div key={dom.id} className="rounded-md border border-border/60 px-3 py-2.5">
                          <div className="flex items-start justify-between gap-2">
                            <div className="min-w-0">
                              <p className="truncate font-mono text-xs font-medium text-foreground" title={dom.domain}>{dom.domain}</p>
                              <p className="font-mono text-[10px] text-muted-foreground">{dom.ip ?? '—'}{dom.country ? ` · ${dom.country}` : ''}</p>
                              {dom.is_third_party && <span className="font-mono text-[9px] text-muted-foreground/50">3rd party</span>}
                            </div>
                            <div className="flex shrink-0 flex-col items-end gap-1">
                              {t?.tls_version && (
                                <Badge variant={t.tls_version === 'TLSv1.3' || t.tls_version === '1.3' ? 'success' : t.tls_version === 'TLSv1.2' || t.tls_version === '1.2' ? 'secondary' : 'destructive'} className="font-mono text-[9px]">
                                  {t.tls_version}
                                </Badge>
                              )}
                              {t && <Badge variant={t.supports_pqc ? 'success' : 'outline'} className="text-[9px]">{t.supports_pqc ? 'PQC ✓' : 'No PQC'}</Badge>}
                              {t?.quantum_risk_score != null && (() => {
                                const qr = t.quantum_risk_score > 1 ? t.quantum_risk_score / 100 : t.quantum_risk_score
                                return (
                                  <span className={cn('font-mono text-[9px]', qr > 0.6 ? 'text-destructive' : qr > 0.3 ? 'text-amber-500' : 'text-emerald-500')}>
                                    Q-Risk {(qr * 100).toFixed(0)}%
                                  </span>
                                )
                              })()}
                            </div>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>

              <div className="px-5 py-4">
                <p className="mb-3 font-mono text-[9px] uppercase tracking-widest text-muted-foreground">Submission Info</p>
                <div className="flex flex-col gap-2">
                  {[
                    { label: 'Submitted', value: new Date(app.submitted_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) },
                    { label: 'Scan Status', value: app.scan_status },
                  ].map(r => (
                    <div key={r.label} className="flex items-center justify-between">
                      <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{r.label}</span>
                      <span className="text-xs text-foreground capitalize">{r.value}</span>
                    </div>
                  ))}
                </div>
              </div>

            </div>
          )}
        </div>
      </SheetContent>
    </Sheet>
  )
}
