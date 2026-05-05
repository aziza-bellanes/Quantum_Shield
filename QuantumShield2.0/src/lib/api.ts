/**
 * API client for the TLS Security Analyzer backend (FastAPI at http://localhost:8000).
 * All authenticated requests attach a Bearer token stored in localStorage.
 */

const BASE_URL = (import.meta.env.VITE_API_URL as string | undefined) ?? 'http://localhost:8000'
const TOKEN_KEY = 'qs_token'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY) ?? sessionStorage.getItem(TOKEN_KEY)
}

/** @param remember true → localStorage (persists); false → sessionStorage (tab-scoped) */
export function saveToken(token: string, remember = true): void {
  if (remember) {
    localStorage.setItem(TOKEN_KEY, token)
  } else {
    sessionStorage.setItem(TOKEN_KEY, token)
  }
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY)
  sessionStorage.removeItem(TOKEN_KEY)
}

// ── Error ─────────────────────────────────────────────────────────────────────
export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
  }
}

// ── Core fetch ────────────────────────────────────────────────────────────────
async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken()
  const headers: Record<string, string> = {
    ...(options.headers as Record<string, string> | undefined),
  }
  if (token) headers['Authorization'] = `Bearer ${token}`
  if (!(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json'
  }

  const res = await fetch(`${BASE_URL}${path}`, { ...options, headers })

  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      if (body.detail) detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
    } catch { /* ignore */ }
    throw new ApiError(res.status, detail)
  }

  if (res.status === 204) return null as T
  return res.json() as Promise<T>
}

// ── Response types (mirror pydantic_schemas) ──────────────────────────────────
export interface TokenResponse {
  access_token: string
  token_type: string
  requires_2fa?: boolean
}

export interface UserOut {
  id: number
  email: string
  name: string | null
  company: string | null
  phone: string | null
  date_of_birth: string | null
  location: string | null
  bio: string | null
  totp_enabled: boolean
  role: string
  created_at: string
}

export interface TotpSetupOut {
  secret: string
  otpauth_uri: string
  qr_data_url: string
}

export interface PreferencesOut {
  email_notifications: boolean
  security_alerts: boolean
  weekly_reports: boolean
  product_updates: boolean
}

export interface ApiKeyOut {
  id: number
  key: string
  created_at: string
  last_used_at: string | null
}

export interface SessionOut {
  id: number
  browser: string | null
  os: string | null
  ip: string | null
  created_at: string
  last_seen_at: string
  is_active: boolean
}

export interface KnowledgeBaseOut {
  id: number
  name: string
  type: string
  records: number
  size: string | null
  status: string
  source: string | null
  last_sync: string | null
}

export interface SyncConfigOut {
  sync_interval: string
  backup_retention: string
}

export interface SyncJobOut {
  id: number
  kb_id: number | null
  kb_name: string
  operation: string        // 'sync' | 'sync-all' | 'import' | 'export'
  status: string           // 'running' | 'success' | 'error'
  started_at: string
  finished_at: string | null
  records_before: number | null
  records_after: number | null
  error_msg: string | null
  triggered_by: string     // 'manual' | 'scheduler'
}

export interface ReportOut {
  id: number
  title: string
  date: string
  type: string
  apps_count: number
  status: string
}

export interface ContactMessageOut {
  id: number
  name: string
  email: string
  subject: string
  message: string
  created_at: string
  is_read: boolean
}

export interface AppOut {
  id: number
  package_name: string
  app_name: string | null
  category: string | null
  install_count: number | null
  rating: number | null
  description: string | null
  owner_id: number | null
  submitted_at: string
  scanned_at: string | null
  made_public_at: string | null
  scan_status: string
  is_public: boolean
  security_score: number | null
  risk_level: string | null
  pqc_readiness_score: number | null
}

export interface StatsOut {
  total_apps: number
  avg_security_score: number
  avg_pqc_readiness: number
  risk_distribution: Record<string, number>
  tls_distribution: Record<string, number>
}

export interface MLPredictionOut {
  id: number
  app_id: number
  security_score: number
  risk_level: string
  pqc_readiness_score: number
  confidence: number | null
  feature_importances: Record<string, number> | null
  predicted_at: string
}

export interface VulnerabilityOut {
  id: number
  tls_result_id: number
  cve_id: string | null
  severity: string
  cvss_score: number | null
  description: string
  reference_url: string | null
}

export interface DomainOut {
  id: number
  domain: string
  ip: string | null
  country: string | null
  is_third_party: boolean
  domain_class: string | null
}

export interface TLSResultOut {
  id: number
  domain_id: number
  tls_version: string | null
  cipher_suite: string | null
  key_exchange: string | null
  cert_expiry: string | null
  cert_issuer: string | null
  cert_validity_days: number | null
  cert_key_type: string | null
  cert_key_bits: number | null
  supports_pqc: boolean
  pqc_group: string | null
  has_ecdh: boolean
  has_rsa_key_exchange: boolean
  flag_legacy_tls: boolean
  flag_rc4_or_3des: boolean
  cipher_strength_score: number | null
  quantum_risk_score: number | null
  security_score: number | null
  scan_date: string
  scan_error: string | null
}

export interface WarrantyOut {
  id: number
  app_id: number
  status: string
  issued_at: string
  expires_at: string | null
  justification: string | null
}

export interface MetricsTimeseriesPoint {
  time: string
  scans: number
  predictions: number
}

export interface SystemHealthOut {
  db_connected: boolean
  total_users: number
  total_apps: number
  total_scans: number
  pending_scans: number
  ml_model_loaded: boolean
}

export interface MlMetricsOut {
  total_predictions: number
  apps_with_predictions: number
  total_apps: number
  coverage_pct: number
  avg_security_score: number
  avg_pqc_readiness: number
  avg_confidence: number | null
  risk_distribution: Record<string, number>
}

// ── Auth API ──────────────────────────────────────────────────────────────────
export const authApi = {
  login(email: string, password: string, totpCode?: string) {
    return request<TokenResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password, totp_code: totpCode ?? null }),
    })
  },
  register(name: string, email: string, password: string, role = 'end_user') {
    return request<TokenResponse>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ name, email, password, role }),
    })
  },
  me() {
    return request<UserOut>('/auth/me')
  },
  googleAuth(credential: string) {
    return request<TokenResponse>('/auth/google', {
      method: 'POST',
      body: JSON.stringify({ credential }),
    })
  },
  githubAuth(code: string) {
    return request<TokenResponse>('/auth/github', {
      method: 'POST',
      body: JSON.stringify({ code }),
    })
  },
  forgotPassword(email: string, totpCode?: string) {
    return request<{ message: string; requires_totp?: boolean; totp_invalid?: boolean }>('/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email, totp_code: totpCode ?? null }),
    })
  },
}

// ── Apps API ──────────────────────────────────────────────────────────────────
export const appsApi = {
  stats() {
    return request<StatsOut>('/apps/stats')
  },
  list(q = '', skip = 0, limit = 10000, sort = 'recent') {
    return request<AppOut[]>(`/apps/?q=${encodeURIComponent(q)}&skip=${skip}&limit=${limit}&sort=${sort}`)
  },
  get(id: number) {
    return request<AppOut>(`/apps/${id}`)
  },
  submit(packageName: string, appName?: string, category?: string) {
    return request<AppOut>('/apps/submit', {
      method: 'POST',
      body: JSON.stringify({ package_name: packageName, app_name: appName, category }),
    })
  },
  uploadApk(file: File, appName?: string, category?: string) {
    const fd = new FormData()
    fd.append('file', file)
    if (appName) fd.append('app_name', appName)
    if (category) fd.append('category', category)
    return request<AppOut>('/apps/upload-apk', { method: 'POST', body: fd })
  },
  /** Analyze a URL, bare domain, or Google Play Store link. */
  analyzeUrl(url: string) {
    return request<AppOut>('/apps/analyze-url', {
      method: 'POST',
      body: JSON.stringify({ url }),
    })
  },
  prediction(id: number) {
    return request<MLPredictionOut>(`/apps/${id}/prediction`)
  },
  vulnerabilities(id: number) {
    return request<VulnerabilityOut[]>(`/apps/${id}/vulnerabilities`)
  },
  domains(id: number) {
    return request<DomainOut[]>(`/apps/${id}/domains`)
  },
  tls(id: number) {
    return request<TLSResultOut[]>(`/apps/${id}/tls`)
  },
  warranty(id: number) {
    return request<WarrantyOut>(`/apps/${id}/warranty`)
  },
  report(id: number, format: 'json' | 'pdf' = 'json') {
    return request(`/apps/${id}/report?format=${format}`)
  },
  setVisibility(id: number, isPublic: boolean) {
    return request<AppOut>(`/apps/${id}/visibility`, {
      method: 'PATCH',
      body: JSON.stringify({ is_public: isPublic }),
    })
  },
  recentCompletions(since: string, ownerId?: number) {
    const q = ownerId != null ? `&owner_id=${ownerId}` : ''
    return request<AppOut[]>(`/apps/recent-completions?since=${encodeURIComponent(since)}${q}`)
  },
  recentPublic(since: string) {
    return request<AppOut[]>(`/apps/recent-public?since=${encodeURIComponent(since)}`)
  },
}

// ── Admin API ─────────────────────────────────────────────────────────────────
export const adminApi = {
  users() {
    return request<UserOut[]>('/admin/users')
  },
  createUser(name: string, email: string, password: string, role: string) {
    return request<{ access_token: string }>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ name, email, password, role }),
    })
  },
  updateRole(userId: number, role: string) {
    return request<UserOut>(`/admin/users/${userId}/role`, {
      method: 'PATCH',
      body: JSON.stringify({ role }),
    })
  },
  deleteUser(userId: number) {
    return request<void>(`/admin/users/${userId}`, { method: 'DELETE' })
  },
  getUserSessions(userId: number) {
    return request<SessionOut[]>(`/admin/users/${userId}/sessions`)
  },
  forceLogout(userId: number) {
    return request<void>(`/admin/users/${userId}/sessions`, { method: 'DELETE' })
  },
  resetUserMfa(userId: number) {
    return request<void>(`/admin/users/${userId}/2fa`, { method: 'DELETE' })
  },
  sendEmail(userId: number, subject: string, body: string) {
    return request<{ message: string }>(`/admin/users/${userId}/send-email`, {
      method: 'POST',
      body: JSON.stringify({ subject, body }),
    })
  },
  seedCsv() {
    return request<{ message: string; apps_created: number; domains_created: number; tls_results_created: number }>('/admin/seed-csv', { method: 'POST' })
  },
  sendPasswordReset(email: string) {
    return request<{ message: string }>('/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email }),
    })
  },
  systemHealth() {
    return request<SystemHealthOut>('/admin/system/health')
  },
  mlMetrics() {
    return request<MlMetricsOut>('/admin/ml-metrics')
  },
  trainModel() {
    return request('/admin/ml/train', { method: 'POST' })
  },
  recentScans() {
    return request<AppOut[]>('/admin/recent-scans')
  },
  scanQueue() {
    return request<AppOut[]>('/admin/scan-queue')
  },
  metricsTimeseries() {
    return request<MetricsTimeseriesPoint[]>('/admin/metrics/timeseries')
  },
}

// ── Health ────────────────────────────────────────────────────────────────────
export const healthApi = {
  check() {
    return request<{ status: string }>('/health')
  },
}

// ── Profile & Password ────────────────────────────────────────────────────────
export const profileApi = {
  update(name: string, email: string, company?: string, phone?: string, date_of_birth?: string, location?: string, bio?: string) {
    return request<UserOut>('/auth/profile', {
      method: 'PATCH',
      body: JSON.stringify({ name, email, company: company || null, phone: phone || null, date_of_birth: date_of_birth || null, location: location || null, bio: bio || null }),
    })
  },
  /** Set the account role (used after first-time OAuth sign-in — end_user or app_owner only). */
  updateRole(role: string) {
    return request<UserOut>('/auth/set-role', {
      method: 'POST',
      body: JSON.stringify({ role }),
    })
  },
  resetPassword(token: string, newPassword: string) {
    return request<{ message: string }>('/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ token, new_password: newPassword }),
    })
  },
  changePassword(currentPassword: string, newPassword: string) {
    return request<void>('/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    })
  },
  getPreferences() {
    return request<PreferencesOut>('/auth/preferences')
  },
  updatePreferences(prefs: Partial<PreferencesOut>) {
    return request<PreferencesOut>('/auth/preferences', {
      method: 'PATCH',
      body: JSON.stringify(prefs),
    })
  },
  getApiKey() {
    return request<ApiKeyOut>('/auth/api-key')
  },
  regenerateApiKey() {
    return request<ApiKeyOut>('/auth/api-key/regenerate', { method: 'POST' })
  },
  getSessions() {
    return request<SessionOut[]>('/auth/sessions')
  },
  revokeSession(sessionId: number) {
    return request<void>(`/auth/sessions/${sessionId}`, { method: 'DELETE' })
  },
  revokeAllSessions() {
    return request<void>('/auth/sessions', { method: 'DELETE' })
  },
  setup2fa() {
    return request<TotpSetupOut>('/auth/2fa/setup', { method: 'POST' })
  },
  verify2fa(code: string) {
    return request<UserOut>('/auth/2fa/verify', { method: 'POST', body: JSON.stringify({ code }) })
  },
  disable2fa(code: string) {
    return request<UserOut>('/auth/2fa/disable', { method: 'POST', body: JSON.stringify({ code }) })
  },
}

// ── Databases ─────────────────────────────────────────────────────────────────
export const databasesApi = {
  list() {
    return request<KnowledgeBaseOut[]>('/admin/databases/')
  },
  listJobs(limit = 50) {
    return request<SyncJobOut[]>(`/admin/databases/jobs?limit=${limit}`)
  },
  syncAll() {
    return request<KnowledgeBaseOut[]>('/admin/databases/sync-all', { method: 'POST' })
  },
  sync(dbId: number) {
    return request<KnowledgeBaseOut>(`/admin/databases/${dbId}/sync`, { method: 'POST' })
  },
  async exportDb(dbId: number, name: string) {
    const token = getToken()
    const res = await fetch(`${BASE_URL}/admin/databases/${dbId}/export`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
    if (!res.ok) throw new ApiError(res.status, res.statusText)
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = name.replace(/ /g, '_') + '.json'
    a.click()
    URL.revokeObjectURL(url)
  },
  async importDb(dbId: number, file: File) {
    const token = getToken()
    const fd = new FormData()
    fd.append('file', file)
    const res = await fetch(`${BASE_URL}/admin/databases/${dbId}/import`, {
      method: 'POST',
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body: fd,
    })
    if (!res.ok) throw new ApiError(res.status, res.statusText)
    return res.json() as Promise<KnowledgeBaseOut>
  },
  getConfig() {
    return request<SyncConfigOut>('/admin/databases/config')
  },
  saveConfig(syncInterval: string, backupRetention: string) {
    return request<SyncConfigOut>('/admin/databases/config', {
      method: 'PATCH',
      body: JSON.stringify({ sync_interval: syncInterval, backup_retention: backupRetention }),
    })
  },
}

// ── Reports ───────────────────────────────────────────────────────────────────
export const reportsApi = {
  list() {
    return request<ReportOut[]>('/reports/')
  },
  regenerate() {
    return request<{ message: string }>('/reports/regenerate', { method: 'POST' })
  },
  async download(reportId: number, title: string) {
    const token = getToken()
    const res = await fetch(`${BASE_URL}/reports/${reportId}/download`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
    if (!res.ok) throw new ApiError(res.status, res.statusText)
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = title.replace(/ /g, '_').replace(/—/g, '-') + '.json'
    a.click()
    URL.revokeObjectURL(url)
  },
}

// ── Contact ───────────────────────────────────────────────────────────────────
export const contactApi = {
  send(name: string, email: string, subject: string, message: string) {
    return request<ContactMessageOut>('/contact/', {
      method: 'POST',
      body: JSON.stringify({ name, email, subject, message }),
    })
  },
}
