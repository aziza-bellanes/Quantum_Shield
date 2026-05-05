export type RiskLevel = 'Low' | 'Medium' | 'High'

export interface App {
  id: number
  name: string
  pkg: string
  category: string
  score: number
  risk: RiskLevel
  tls: string
  pqc: boolean
  rating: number
  downloads: string
  description: string
  lastAudit: string
}

export interface TlsEntry {
  version: string
  count: number
  color: string
}

export interface RiskEntry {
  name: string
  value: number
  color: string
  fill: string
}

export type Page = 'dashboard' | 'browse' | 'account' | 'contact' | 'reports' | 'analyze' | 'my-apps' | 'users' | 'system' | 'database'

// ── Auth ──────────────────────────────────────────────────────────────────────
export type UserRole = 'end_user' | 'app_owner' | 'admin'

export interface User {
  id: string
  name: string
  email: string
  company: string | null
  phone: string | null
  dateOfBirth: string | null
  location: string | null
  bio: string | null
  totpEnabled: boolean
  role: UserRole
  initials: string
  joinDate: string
}

// ── Reports ───────────────────────────────────────────────────────────────────
export type ReportType = 'weekly' | 'monthly' | 'quarterly' | 'custom'
export type ReportStatus = 'ready' | 'generating' | 'failed'

export interface Report {
  id: number
  title: string
  date: string
  type: ReportType
  appsCount: number
  status: ReportStatus
}

// ── Owner apps ────────────────────────────────────────────────────────────────
export type AppStatus = 'Analyzed' | 'Analyzing' | 'Failed'

export interface OwnedApp {
  id: number
  name: string
  pkg: string
  version: string
  uploadedAt: string
  status: AppStatus
  score: number | null
  risk: RiskLevel | null
  tls: string | null
  pqc: boolean | null
  vulns: number | null
}

// ── Admin: managed users ──────────────────────────────────────────────────────
export type UserStatus = 'active' | 'inactive'

export interface ManagedUser {
  id: string
  name: string
  email: string
  role: UserRole
  status: UserStatus
  joinDate: string
  lastLogin: string
  appsAnalyzed: number
}

// ── Admin: system services ────────────────────────────────────────────────────
export type ServiceHealth = 'healthy' | 'degraded' | 'down'

export interface SystemService {
  name: string
  status: ServiceHealth
  uptime: number
  lastCheck: string
}

export interface CpuDataPoint { time: string; usage: number }
export interface ApiRequestDataPoint { time: string; requests: number }

// ── Admin: databases ──────────────────────────────────────────────────────────
export type DbStatus = 'synced' | 'syncing' | 'error'

export interface Database {
  id: number
  name: string
  type: string
  records: number
  size: string
  status: DbStatus
  source: string
  lastSync: string
}
