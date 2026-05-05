import React, { useEffect, useState } from 'react'
import {
  Shield, Lock, TrendingUp, Check,
} from 'lucide-react'
import {
  Card, CardContent, CardHeader, CardTitle, CardDescription,
} from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Separator } from '../components/ui/separator'
import { Skeleton } from '../components/ui/skeleton'
import { TlsBarChart } from '../components/charts/TlsBarChart'
import { RiskDonutChart } from '../components/charts/RiskDonutChart'
import { appsApi } from '../lib/api'
import type { AppOut, StatsOut } from '../lib/api'
import { scoreColor, riskVariant } from '../lib/utils'
import type { RiskLevel, TlsEntry, RiskEntry } from '../lib/types'
import { useAuth } from '../context/AuthContext'

// ── Animated counter ──────────────────────────────────────────────────────────
const AnimatedNumber: React.FC<{
  to: number
  duration?: number
  decimals?: number
}> = ({ to, duration = 1000, decimals = 0 }) => {
  const [val, setVal] = useState(0)

  useEffect(() => {
    const start = performance.now()
    const tick = (now: number) => {
      const p = Math.min((now - start) / duration, 1)
      const ease = 1 - Math.pow(1 - p, 4)
      setVal(parseFloat((ease * to).toFixed(decimals)))
      if (p < 1) requestAnimationFrame(tick)
    }
    requestAnimationFrame(tick)
  }, [to, duration, decimals])

  return <>{decimals > 0 ? val.toFixed(decimals) : Math.round(val).toLocaleString()}</>
}

// ── Score ring — pure SVG geometry ────────────────────────────────────────────
const ScoreRing: React.FC<{ value: number; size?: number }> = ({
  value,
  size = 88,
}) => {
  const r = (size - 10) / 2
  const circ = 2 * Math.PI * r
  const offset = circ * (1 - value / 100)

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        style={{ transform: 'rotate(-90deg)' }}
      >
        <circle
          cx={size / 2} cy={size / 2} r={r}
          fill="none"
          stroke="hsl(var(--muted))"
          strokeWidth="7"
        />
        <circle
          cx={size / 2} cy={size / 2} r={r}
          fill="none"
          stroke="hsl(var(--foreground))"
          strokeWidth="7"
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 1.2s cubic-bezier(.16,1,.3,1)' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono text-xl font-bold leading-none text-foreground">
          {value}
        </span>
        <span className="font-mono text-[9px] text-muted-foreground">/100</span>
      </div>
    </div>
  )
}

// ── KPI card ──────────────────────────────────────────────────────────────────
interface KpiCardProps {
  label: string
  value: React.ReactNode
  sub: string
  icon: React.ReactNode
  iconBg: string
  delay?: number
}

const KpiCard: React.FC<KpiCardProps> = ({
  label, value, sub, icon, iconBg, delay = 0,
}) => {
  const [visible, setVisible] = useState(false)

  useEffect(() => {
    const t = setTimeout(() => setVisible(true), delay)
    return () => clearTimeout(t)
  }, [delay])

  return (
    <Card
      className="transition-all duration-500"
      style={{
        opacity: visible ? 1 : 0,
        transform: visible ? 'translateY(0)' : 'translateY(10px)',
      }}
    >
      <CardContent className="flex items-center justify-between p-5">
        <div>
          <p className="font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
            {label}
          </p>
          <div className="mt-1.5 font-mono text-2xl font-bold leading-none tracking-tight text-foreground">
            {value}
          </div>
          <p className="mt-1.5 text-[11px] text-muted-foreground">{sub}</p>
        </div>
        <div
          className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border ${iconBg}`}
        >
          {icon}
        </div>
      </CardContent>
    </Card>
  )
}

// ── Recent audits table ───────────────────────────────────────────────────────
const RecentAuditsTable: React.FC<{ apps: AppOut[] }> = ({ apps }) => (
  <Card>
    <CardHeader>
      <CardTitle>Recent Audits</CardTitle>
      <CardDescription>Latest application security assessments</CardDescription>
    </CardHeader>
    <CardContent className="p-0">
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b bg-muted/30">
              {['Application', 'Category', 'Score', 'Risk', 'PQC', 'Status', 'Submitted'].map(h => (
                <th
                  key={h}
                  className="whitespace-nowrap px-5 py-2.5 text-left font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground"
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {apps.map(app => {
              const score = Math.round(app.security_score ?? 0)
              const risk = (app.risk_level ?? 'Medium') as RiskLevel
              const pqc = (app.pqc_readiness_score ?? 0) > 50
              return (
                <tr
                  key={app.id}
                  className="border-b border-border/50 transition-colors last:border-0 hover:bg-muted/20"
                >
                  <td className="px-5 py-3">
                    <div className="font-medium text-foreground">{app.app_name ?? app.package_name}</div>
                    <div className="font-mono text-[10px] text-muted-foreground">{app.package_name}</div>
                  </td>
                  <td className="px-5 py-3 text-muted-foreground">{app.category ?? '—'}</td>
                  <td className="px-5 py-3">
                    {app.security_score != null ? (
                      <span className={`font-mono font-bold ${scoreColor(score)}`}>{score}</span>
                    ) : (
                      <span className="font-mono text-muted-foreground">—</span>
                    )}
                  </td>
                  <td className="px-5 py-3">
                    {app.risk_level ? (
                      <Badge variant={riskVariant(risk)}>{risk}</Badge>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </td>
                  <td className="px-5 py-3">
                    {app.pqc_readiness_score != null ? (
                      pqc ? (
                        <span className="flex items-center gap-1 text-emerald-500 dark:text-emerald-400">
                          <Check size={12} strokeWidth={2.5} />
                          <span className="font-mono text-[11px] font-semibold">Yes</span>
                        </span>
                      ) : (
                        <span className="font-mono text-[11px] text-muted-foreground">No</span>
                      )
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </td>
                  <td className="px-5 py-3">
                    <span className="font-mono text-[10px] capitalize text-muted-foreground">
                      {app.scan_status}
                    </span>
                  </td>
                  <td className="px-5 py-3 font-mono text-[10px] text-muted-foreground">
                    {new Date(app.submitted_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}
                  </td>
                </tr>
              )
            })}
            {apps.length === 0 && (
              <tr>
                <td colSpan={7} className="px-5 py-10 text-center text-sm text-muted-foreground">
                  No applications yet — submit one to get started.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </CardContent>
  </Card>
)

const riskColors: Record<string, string> = {
  Low: '#22c55e', Medium: '#f59e0b', High: '#ef4444', Critical: '#7f1d1d',
}
const tlsColors: Record<string, string> = {
  'TLSv1.3': '#22c55e', 'TLSv1.2': '#3b82f6', 'TLSv1.1': '#f59e0b', 'TLSv1.0': '#ef4444', 'Unknown': '#6b7280',
}

// ── Page ──────────────────────────────────────────────────────────────────────
export const DashboardPage: React.FC = () => {
  const { user } = useAuth()
  // Only app_owners get a portfolio-scoped view (their own apps only).
  // Admins and end_users both see global stats (backend scoping mirrors this).
  const isOwner = user?.role === 'app_owner'
  const [bannerVisible, setBannerVisible] = useState(false)
  const [loading, setLoading] = useState(true)
  const [stats, setStats] = useState<StatsOut | null>(null)
  const [apps, setApps] = useState<AppOut[]>([])
  const [tlsData, setTlsData] = useState<TlsEntry[]>([])
  const [riskData, setRiskData] = useState<RiskEntry[]>([])

  useEffect(() => {
    const t = setTimeout(() => setBannerVisible(true), 40)
    return () => clearTimeout(t)
  }, [])

  useEffect(() => {
    // Defer setState to avoid synchronous call inside effect body
    Promise.resolve().then(() => setLoading(true))
    // Both owners and end-users now use appsApi.stats() — the backend automatically
    // scopes results to the caller's own apps when the role is app_owner/admin,
    // and returns global stats for end_user. This gives owners a real TLS
    // distribution chart from their domains instead of an empty chart.
    Promise.all([
      appsApi.stats(),
      appsApi.list('', 0, isOwner ? 200 : 10),
    ]).then(([s, list]) => {
      setStats(s)
      const tls: TlsEntry[] = Object.entries(s.tls_distribution).map(([version, count]) => ({
        version: version.replace('TLSv', ''),
        count,
        color: tlsColors[version] ?? '#6b7280',
      }))
      setTlsData(tls)
      const risk: RiskEntry[] = Object.entries(s.risk_distribution)
        .filter(([, v]) => v > 0)
        .map(([name, value]) => ({ name, value, color: riskColors[name] ?? '#6b7280', fill: riskColors[name] ?? '#6b7280' }))
      setRiskData(risk)
      // Owners see their own apps; end-users see the most recent public apps
      setApps(isOwner ? list.slice(0, 10) : list)
    }).catch(() => {}).finally(() => setLoading(false))
  }, [isOwner, user])

  const avgScore = Math.round(stats?.avg_security_score ?? 0)
  const avgPqc = Math.round(stats?.avg_pqc_readiness ?? 0)
  const totalApps = stats?.total_apps ?? 0

  // Determine dominant TLS version for KPI card
  const dominantTls = tlsData.length > 0
    ? tlsData.reduce((a, b) => (a.count > b.count ? a : b)).version
    : '—'

  // Dominant risk level
  const dominantRisk = riskData.length > 0
    ? riskData.reduce((a, b) => (a.value > b.value ? a : b)).name
    : 'N/A'

  return (
    <div className="flex flex-col gap-5 p-6">

      {/* ── Score banner ── */}
      <Card
        className="border-l-[3px] border-l-foreground transition-all duration-500"
        style={{
          opacity: bannerVisible ? 1 : 0,
          transform: bannerVisible ? 'translateY(0)' : 'translateY(8px)',
        }}
      >
        <CardContent className="flex flex-col items-start justify-between gap-5 p-5 sm:flex-row sm:items-center">
          <div className="flex items-center gap-4">
            <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg bg-foreground text-background">
              <Shield size={20} />
            </div>
            <div>
              <h2 className="text-sm font-semibold tracking-tight text-foreground">
                Overall Security Score
              </h2>
              <p className="mt-0.5 text-xs text-muted-foreground">
                Comprehensive security assessment across all monitored applications
              </p>
            </div>
          </div>

          <div className="flex shrink-0 items-center gap-6">
            {loading
              ? <Skeleton className="h-[88px] w-[88px] rounded-full" />
              : <ScoreRing value={avgScore} />}
            <Separator orientation="vertical" className="hidden h-14 sm:block" />
            <div className="text-right sm:text-left">
              <p className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">
                Risk Level
              </p>
              {loading
                ? <Skeleton className="mt-1 h-7 w-20" />
                : <p className={`mt-1 font-mono text-xl font-bold ${
                    dominantRisk === 'Low' ? 'text-emerald-500 dark:text-emerald-400'
                    : dominantRisk === 'High' || dominantRisk === 'Critical' ? 'text-red-500'
                    : 'text-amber-500'
                  }`}>
                    {dominantRisk}
                  </p>}
              <p className="text-[10px] text-muted-foreground">Security Status</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* ── KPIs ── */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <KpiCard
          label="TLS Version"
          value={loading ? <Skeleton className="h-7 w-16" /> : (dominantTls !== '—' ? dominantTls : '—')}
          sub="Most Common Protocol"
          delay={80}
          iconBg="border-emerald-500/20 bg-emerald-500/10"
          icon={<Lock size={16} className="text-emerald-500 dark:text-emerald-400" />}
        />
        <KpiCard
          label="PQC Readiness"
          value={loading ? <Skeleton className="h-7 w-16" /> : <><AnimatedNumber to={avgPqc} />%</>}
          sub="Quantum-Safe Score"
          delay={160}
          iconBg="border-primary/20 bg-primary/10"
          icon={<Shield size={16} className="text-primary" />}
        />
        <KpiCard
          label="Apps Analyzed"
          value={loading ? <Skeleton className="h-7 w-12" /> : <AnimatedNumber to={totalApps} />}
          sub="Total in database"
          delay={240}
          iconBg="border-violet-500/20 bg-violet-500/10"
          icon={<TrendingUp size={16} className="text-violet-500" />}
        />
      </div>

      {/* ── Charts ── */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {tlsData.length > 0 ? (
          <TlsBarChart data={tlsData} />
        ) : (
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">TLS Distribution</CardTitle>
              <CardDescription className="text-xs">
                {isOwner ? 'TLS breakdown is available in app details' : 'No TLS data yet'}
              </CardDescription>
            </CardHeader>
            <CardContent className="flex items-center justify-center py-10 text-xs text-muted-foreground">
              {isOwner ? 'View individual apps to see TLS results' : 'Submit apps to populate this chart'}
            </CardContent>
          </Card>
        )}
        <RiskDonutChart data={riskData} />
      </div>

      {/* ── Table ── */}
      <RecentAuditsTable apps={apps} />
    </div>
  )
}
