import type {
  App, TlsEntry, RiskEntry,
  Report, OwnedApp, ManagedUser,
  SystemService, CpuDataPoint, ApiRequestDataPoint, Database,
} from './types'

export const APPS: App[] = [
  {
    id: 1,
    name: 'SecureBank Mobile',
    pkg: 'com.securebank.mobile',
    category: 'Finance',
    score: 95,
    risk: 'Low',
    tls: '1.3',
    pqc: true,
    rating: 4.8,
    downloads: '10M+',
    description: 'Banking & financial transactions with end-to-end encryption.',
    lastAudit: '2026-03-01',
  },
  {
    id: 2,
    name: 'ShopEasy E-Commerce',
    pkg: 'com.shopeasy.app',
    category: 'Shopping',
    score: 72,
    risk: 'Medium',
    tls: '1.2',
    pqc: false,
    rating: 4.3,
    downloads: '5M+',
    description: 'E-commerce platform with payment gateway integration.',
    lastAudit: '2026-02-14',
  },
  {
    id: 3,
    name: 'HealthTracker Pro',
    pkg: 'com.healthtracker.pro',
    category: 'Health',
    score: 88,
    risk: 'Low',
    tls: '1.3',
    pqc: true,
    rating: 4.6,
    downloads: '1M+',
    description: 'Personal health data monitoring and medical record sync.',
    lastAudit: '2026-03-10',
  },
  {
    id: 4,
    name: 'SocialConnect',
    pkg: 'com.socialconnect.app',
    category: 'Social',
    score: 58,
    risk: 'High',
    tls: '1.1',
    pqc: false,
    rating: 4.1,
    downloads: '50M+',
    description: 'Social networking with messaging and media sharing.',
    lastAudit: '2026-01-22',
  },
  {
    id: 5,
    name: 'CloudDrive Storage',
    pkg: 'com.clouddrive.storage',
    category: 'Productivity',
    score: 91,
    risk: 'Low',
    tls: '1.3',
    pqc: true,
    rating: 4.7,
    downloads: '20M+',
    description: 'Cloud storage with zero-knowledge encryption architecture.',
    lastAudit: '2026-03-15',
  },
  {
    id: 6,
    name: 'GameZone',
    pkg: 'com.gamezone.gaming',
    category: 'Gaming',
    score: 64,
    risk: 'Medium',
    tls: '1.2',
    pqc: false,
    rating: 4.5,
    downloads: '100M+',
    description: 'Mobile gaming platform with in-app purchases and leaderboards.',
    lastAudit: '2026-02-28',
  },
]

export const TLS_DATA: TlsEntry[] = [
  { version: '1.0', count: 38, color: 'hsl(var(--destructive))' },
  { version: '1.1', count: 182, color: 'hsl(38 92% 50%)' },
  { version: '1.2', count: 580, color: 'hsl(48 96% 53%)' },
  { version: '1.3', count: 510, color: 'hsl(142 71% 45%)' },
]

export const RISK_DATA: RiskEntry[] = [
  { name: 'Low', value: 512, color: 'hsl(142 71% 45%)', fill: 'hsl(142 71% 45%)' },
  { name: 'Medium', value: 345, color: 'hsl(38 92% 50%)', fill: 'hsl(38 92% 50%)' },
  { name: 'High', value: 143, color: 'hsl(var(--destructive))', fill: 'hsl(var(--destructive))' },
]

// ── Reports ───────────────────────────────────────────────────────────────────
export const REPORTS: Report[] = [
  { id: 1, title: 'Weekly Security Digest — Apr 7', date: '2026-04-07', type: 'weekly', appsCount: 14, status: 'ready' },
  { id: 2, title: 'Weekly Security Digest — Mar 31', date: '2026-03-31', type: 'weekly', appsCount: 11, status: 'ready' },
  { id: 3, title: 'Monthly Overview — March 2026', date: '2026-03-01', type: 'monthly', appsCount: 47, status: 'ready' },
  { id: 4, title: 'Quarterly PQC Readiness — Q1 2026', date: '2026-01-01', type: 'quarterly', appsCount: 132, status: 'ready' },
  { id: 5, title: 'Custom Audit — Finance Apps', date: '2026-04-02', type: 'custom', appsCount: 8, status: 'ready' },
  { id: 6, title: 'Monthly Overview — April 2026', date: '2026-04-01', type: 'monthly', appsCount: 0, status: 'generating' },
]

// ── App Owner portfolio ───────────────────────────────────────────────────────
export const OWNED_APPS: OwnedApp[] = [
  { id: 1, name: 'PayFlow SDK', pkg: 'com.payflow.sdk', version: '3.2.1', uploadedAt: '2026-04-01', status: 'Analyzed', score: 91, risk: 'Low', tls: '1.3', pqc: true, vulns: 1 },
  { id: 2, name: 'AuthGate Mobile', pkg: 'com.authgate.mobile', version: '1.8.0', uploadedAt: '2026-03-28', status: 'Analyzed', score: 67, risk: 'Medium', tls: '1.2', pqc: false, vulns: 5 },
  { id: 3, name: 'DataSync Agent', pkg: 'com.datasync.agent', version: '2.0.4', uploadedAt: '2026-04-08', status: 'Analyzing', score: null, risk: null, tls: null, pqc: null, vulns: null },
  { id: 4, name: 'Legacy Reporter', pkg: 'com.legacy.reporter', version: '0.9.2', uploadedAt: '2026-03-15', status: 'Failed', score: null, risk: null, tls: null, pqc: null, vulns: null },
]

// ── Admin: managed users ──────────────────────────────────────────────────────
export const MANAGED_USERS: ManagedUser[] = [
  { id: '1', name: 'Alex User', email: 'user@quantumshield.io', role: 'end_user', status: 'active', joinDate: '2026-01-15', lastLogin: '2026-04-09', appsAnalyzed: 3 },
  { id: '2', name: 'Dev Owner', email: 'dev@quantumshield.io', role: 'app_owner', status: 'active', joinDate: '2026-03-02', lastLogin: '2026-04-08', appsAnalyzed: 12 },
  { id: '3', name: 'Admin User', email: 'admin@quantumshield.io', role: 'admin', status: 'active', joinDate: '2025-11-01', lastLogin: '2026-04-09', appsAnalyzed: 0 },
  { id: '4', name: 'Sarah Chen', email: 'schen@techcorp.io', role: 'app_owner', status: 'active', joinDate: '2026-02-14', lastLogin: '2026-04-07', appsAnalyzed: 8 },
  { id: '5', name: 'Marcus Webb', email: 'mwebb@financegroup.com', role: 'app_owner', status: 'inactive', joinDate: '2025-12-20', lastLogin: '2026-03-10', appsAnalyzed: 4 },
  { id: '6', name: 'Priya Nair', email: 'pnair@healthstart.io', role: 'end_user', status: 'active', joinDate: '2026-03-20', lastLogin: '2026-04-06', appsAnalyzed: 1 },
  { id: '7', name: 'Jordan Kim', email: 'jkim@devstudio.app', role: 'end_user', status: 'active', joinDate: '2026-04-01', lastLogin: '2026-04-09', appsAnalyzed: 0 },
  { id: '8', name: 'Leo Vance', email: 'lvance@securenet.co', role: 'app_owner', status: 'inactive', joinDate: '2025-10-05', lastLogin: '2026-02-28', appsAnalyzed: 21 },
]

// ── Admin: system services ────────────────────────────────────────────────────
export const SYSTEM_SERVICES: SystemService[] = [
  { name: 'API Gateway', status: 'healthy', uptime: 99.98, lastCheck: '2026-04-09T09:45:00Z' },
  { name: 'PQC Analyzer', status: 'healthy', uptime: 99.95, lastCheck: '2026-04-09T09:44:30Z' },
  { name: 'Auth Service', status: 'healthy', uptime: 100.0, lastCheck: '2026-04-09T09:45:00Z' },
  { name: 'Report Engine', status: 'degraded', uptime: 97.2, lastCheck: '2026-04-09T09:40:00Z' },
  { name: 'CVE Sync Worker', status: 'healthy', uptime: 99.91, lastCheck: '2026-04-09T09:43:00Z' },
]

export const CPU_DATA: CpuDataPoint[] = [
  { time: '00:00', usage: 18 }, { time: '03:00', usage: 14 }, { time: '06:00', usage: 22 },
  { time: '09:00', usage: 45 }, { time: '12:00', usage: 38 }, { time: '15:00', usage: 52 },
  { time: '18:00', usage: 34 }, { time: '21:00', usage: 26 },
]

export const API_REQUESTS_DATA: ApiRequestDataPoint[] = [
  { time: '00:00', requests: 12400 }, { time: '03:00', requests: 8900 }, { time: '06:00', requests: 21000 },
  { time: '09:00', requests: 68000 }, { time: '12:00', requests: 94000 }, { time: '15:00', requests: 87000 },
  { time: '18:00', requests: 61000 }, { time: '21:00', requests: 45000 },
]

// ── Admin: databases ──────────────────────────────────────────────────────────
export const DATABASES: Database[] = [
  { id: 1, name: 'CVE Vulnerability Feed', type: 'NVD CVE Feed', records: 248312, size: '1.2 GB', status: 'synced', source: 'nvd.nist.gov', lastSync: '2026-04-09T06:00:00Z' },
  { id: 2, name: 'PQC Algorithm Registry', type: 'Internal Registry', records: 142, size: '4 MB', status: 'synced', source: 'Internal', lastSync: '2026-04-08T12:00:00Z' },
  { id: 3, name: 'TLS Cipher Suites', type: 'IANA Registry', records: 534, size: '2 MB', status: 'synced', source: 'iana.org', lastSync: '2026-04-07T00:00:00Z' },
  { id: 4, name: 'Certificate Authorities', type: 'CA Bundle', records: 1821, size: '18 MB', status: 'syncing', source: 'Mozilla CA Store', lastSync: '2026-04-09T09:30:00Z' },
]
