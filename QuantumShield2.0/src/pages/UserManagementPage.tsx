import React, { useState, useMemo, useEffect, useCallback } from 'react'
import {
  Users, MoreVertical, UserPlus, Trash2, RefreshCw, Mail,
  Eye, EyeOff, AlertTriangle, X, LogOut, ShieldOff, Info,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Separator } from '../components/ui/separator'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '../components/ui/select'
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
} from '../components/ui/dropdown-menu'
import { adminApi, ApiError } from '../lib/api'
import type { UserOut, SessionOut } from '../lib/api'
import { roleLabel, formatDateTime } from '../lib/utils'
import type { UserRole } from '../lib/types'

/** Returns Tailwind classes that make the SelectTrigger look like a role badge. */
function roleTriggerClass(role: string): string {
  const base = 'h-6 rounded-full px-2.5 font-mono text-[10px] border w-auto gap-1'
  if (role === 'admin')
    return `${base} border-destructive/40 bg-destructive/10 text-destructive hover:bg-destructive/20 focus-visible:ring-destructive/30`
  if (role === 'app_owner')
    return `${base} border-border bg-secondary text-secondary-foreground hover:bg-secondary/80`
  return `${base} border-border bg-transparent text-foreground hover:bg-muted/50`
}

// ── Delete confirmation modal ─────────────────────────────────────────────────
const DeleteModal: React.FC<{
  user: UserOut
  onConfirm: () => void
  onCancel: () => void
  loading: boolean
}> = ({ user, onConfirm, onCancel, loading }) => (
  <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
    <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onCancel} />
    <div className="relative flex w-full max-w-sm flex-col rounded-xl border border-border bg-background p-6 shadow-2xl">
      <div className="flex items-start gap-3">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-destructive/10 border border-destructive/20">
          <AlertTriangle size={16} className="text-destructive" />
        </div>
        <div>
          <h2 className="text-sm font-semibold text-foreground">Delete user</h2>
          <p className="mt-1 text-xs text-muted-foreground">
            Are you sure you want to delete <strong>{user.name ?? user.email}</strong>? This action is permanent and cannot be undone.
          </p>
        </div>
      </div>
      <div className="mt-5 flex justify-end gap-2">
        <Button variant="outline" size="sm" className="h-8 text-xs" onClick={onCancel} disabled={loading}>
          Cancel
        </Button>
        <Button variant="destructive" size="sm" className="h-8 gap-1.5 text-xs" onClick={onConfirm} disabled={loading} aria-busy={loading}>
          {loading
            ? <><span aria-hidden="true" className="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent" /> Deleting…</>
            : <><Trash2 size={12} /> Delete</>}
        </Button>
      </div>
    </div>
  </div>
)

// ── User Detail modal (profile info + login history) ──────────────────────────
const UserDetailModal: React.FC<{
  user: UserOut
  onClose: () => void
}> = ({ user, onClose }) => {
  const [sessions, setSessions] = useState<SessionOut[]>([])
  const [loadingSessions, setLoadingSessions] = useState(true)

  useEffect(() => {
    adminApi.getUserSessions(user.id)
      .then(setSessions)
      .catch(() => setSessions([]))
      .finally(() => setLoadingSessions(false))
  }, [user.id])

  const name = user.name ?? user.email
  const initials = name.trim().split(/\s+/).map(w => w[0]).join('').slice(0, 2).toUpperCase()

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative flex w-full max-w-lg flex-col rounded-xl border border-border bg-background shadow-2xl max-h-[85vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-foreground font-mono text-sm font-bold text-background">
              {initials}
            </div>
            <div>
              <p className="text-sm font-semibold text-foreground">{name}</p>
              <p className="text-[11px] text-muted-foreground">{user.email}</p>
            </div>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors">
            <X size={16} />
          </button>
        </div>

        <div className="overflow-y-auto p-5 flex flex-col gap-5">
          {/* Profile info */}
          <div>
            <p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Profile</p>
            <div className="grid grid-cols-2 gap-x-6 gap-y-2.5">
              {[
                { label: 'Role', value: roleLabel(user.role as UserRole) },
                { label: 'Company', value: user.company || '—' },
                { label: 'Phone', value: user.phone || '—' },
                { label: 'Location', value: user.location || '—' },
                { label: 'Date of Birth', value: user.date_of_birth || '—' },
                { label: '2FA Enabled', value: user.totp_enabled ? 'Yes' : 'No' },
                { label: 'Member Since', value: formatDateTime(user.created_at) },
              ].map(({ label, value }) => (
                <div key={label}>
                  <p className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground">{label}</p>
                  <p className="mt-0.5 text-xs text-foreground">{value}</p>
                </div>
              ))}
            </div>
            {user.bio && (
              <div className="mt-3">
                <p className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground">Bio</p>
                <p className="mt-0.5 text-xs text-muted-foreground leading-relaxed">{user.bio}</p>
              </div>
            )}
          </div>

          <Separator />

          {/* Login history */}
          <div>
            <p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
              Login History ({sessions.length} session{sessions.length !== 1 ? 's' : ''})
            </p>
            {loadingSessions ? (
              <p className="text-xs text-muted-foreground">Loading sessions…</p>
            ) : sessions.length === 0 ? (
              <p className="text-xs text-muted-foreground">No sessions recorded.</p>
            ) : (
              <div className="flex flex-col gap-2">
                {sessions.map((s, i) => (
                  <div key={s.id} className="flex items-center justify-between rounded-lg border border-border/60 px-3 py-2.5">
                    <div>
                      <p className="text-xs font-medium text-foreground">
                        {s.browser ?? 'Unknown browser'} · {s.os ?? 'Unknown OS'}
                      </p>
                      <p className="font-mono text-[10px] text-muted-foreground">
                        {s.ip ?? '—'} · Last seen {formatDateTime(s.last_seen_at)}
                      </p>
                    </div>
                    {i === 0 && s.is_active && (
                      <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] text-emerald-500">● Active</span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="border-t border-border px-5 py-3 flex justify-end">
          <Button variant="outline" size="sm" className="h-8 text-xs" onClick={onClose}>Close</Button>
        </div>
      </div>
    </div>
  )
}

// ── Add user modal ────────────────────────────────────────────────────────────
const AddUserModal: React.FC<{
  onCreated: (u: UserOut) => void
  onClose: () => void
}> = ({ onCreated, onClose }) => {
  const [form, setForm] = useState({ name: '', email: '', password: '', role: 'end_user' })
  const [showPw, setShowPw] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!form.name || !form.email || !form.password) { setError('All fields are required.'); return }
    if (form.password.length < 8) { setError('Password must be at least 8 characters.'); return }
    setSaving(true)
    setError('')
    try {
      await adminApi.createUser(form.name, form.email, form.password, form.role)
      const users = await adminApi.users()
      const created = users.find(u => u.email === form.email)
      if (created) onCreated(created)
      onClose()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to create user.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative flex w-full max-w-md flex-col rounded-xl border border-border bg-background p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-foreground">Add New User</h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors"><X size={16} /></button>
        </div>
        <form onSubmit={handleSubmit} noValidate className="flex flex-col gap-3.5">
          <div>
            <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Full Name</label>
            <Input placeholder="Jane Doe" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} className="h-8 text-xs" />
          </div>
          <div>
            <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Email Address</label>
            <Input type="email" placeholder="jane@company.com" value={form.email} onChange={e => setForm(f => ({ ...f, email: e.target.value }))} className="h-8 text-xs" />
          </div>
          <div>
            <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Temporary Password</label>
            <div className="relative">
              <Input
                type={showPw ? 'text' : 'password'}
                placeholder="Min. 8 characters"
                value={form.password}
                onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                className="h-8 pr-9 text-xs"
              />
              <button type="button" tabIndex={-1}
                onClick={() => setShowPw(v => !v)}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                aria-label={showPw ? 'Hide password' : 'Show password'}
              >
                {showPw ? <EyeOff size={13} /> : <Eye size={13} />}
              </button>
            </div>
          </div>
          <div>
            <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Role</label>
            <Select value={form.role} onValueChange={val => setForm(f => ({ ...f, role: val }))}>
              <SelectTrigger className="h-8 w-full text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="end_user">End User</SelectItem>
                <SelectItem value="app_owner">App Owner</SelectItem>
                <SelectItem value="admin">Administrator</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {error && <p className="text-[11px] text-destructive">{error}</p>}
          <div className="mt-1 flex justify-end gap-2">
            <Button variant="outline" type="button" size="sm" className="h-8 text-xs" onClick={onClose}>Cancel</Button>
            <Button type="submit" size="sm" className="h-8 gap-1.5 text-xs" disabled={saving} aria-busy={saving}>
              {saving
                ? <><span aria-hidden="true" className="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent" /> Creating…</>
                : <><UserPlus size={12} /> Create User</>}
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Send email modal ──────────────────────────────────────────────────────────
const SendEmailModal: React.FC<{
  user: UserOut
  onClose: () => void
}> = ({ user, onClose }) => {
  const [subject, setSubject] = useState('')
  const [body, setBody] = useState('')
  const [sending, setSending] = useState(false)
  const [result, setResult] = useState<{ ok: boolean; msg: string } | null>(null)

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!subject.trim() || !body.trim()) return
    setSending(true)
    setResult(null)
    try {
      await adminApi.sendEmail(user.id, subject.trim(), body.trim())
      setResult({ ok: true, msg: `Email sent to ${user.email}` })
      setTimeout(onClose, 1800)
    } catch (err) {
      setResult({ ok: false, msg: err instanceof ApiError ? err.message : 'Failed to send email.' })
    } finally {
      setSending(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative flex w-full max-w-md flex-col rounded-xl border border-border bg-background p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-foreground">Send Email</h2>
            <p className="text-[11px] text-muted-foreground">To: {user.email}</p>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors"><X size={16} /></button>
        </div>
        <form onSubmit={handleSend} className="flex flex-col gap-3.5">
          <div>
            <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Subject</label>
            <Input
              placeholder="Email subject…"
              value={subject}
              onChange={e => setSubject(e.target.value)}
              className="h-8 text-xs"
              required
            />
          </div>
          <div>
            <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Message</label>
            <textarea
              placeholder="Write your message here…"
              value={body}
              onChange={e => setBody(e.target.value)}
              rows={5}
              required
              className="w-full rounded-lg border border-input bg-transparent px-3 py-2 text-xs text-foreground placeholder:text-muted-foreground outline-none focus:border-ring resize-none"
            />
          </div>
          {result && (
            <p className={`text-[11px] ${result.ok ? 'text-emerald-500' : 'text-destructive'}`}>{result.msg}</p>
          )}
          <div className="mt-1 flex justify-end gap-2">
            <Button variant="outline" type="button" size="sm" className="h-8 text-xs" onClick={onClose}>Cancel</Button>
            <Button type="submit" size="sm" className="h-8 gap-1.5 text-xs" disabled={sending || !subject.trim() || !body.trim()} aria-busy={sending}>
              {sending
                ? <><span aria-hidden="true" className="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent" /> Sending…</>
                : <><Mail size={12} /> Send Email</>}
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Three-dots dropdown menu ──────────────────────────────────────────────────
const UserMenu: React.FC<{
  user: UserOut
  onViewDetails: () => void
  onSendEmail: () => void
  onResetPassword: () => void
  onForceLogout: () => void
  onResetMfa: () => void
  onDelete: () => void
}> = ({ user, onViewDetails, onSendEmail, onResetPassword, onForceLogout, onResetMfa, onDelete }) => (
  <DropdownMenu>
    <DropdownMenuTrigger asChild>
      <Button variant="ghost" size="icon" className="h-7 w-7" title="More actions">
        <MoreVertical size={13} />
      </Button>
    </DropdownMenuTrigger>
    <DropdownMenuContent align="end" className="min-w-[190px]">
      <DropdownMenuItem onClick={onViewDetails} className="gap-2.5 text-xs">
        <Info size={12} className="text-muted-foreground" /> View details
      </DropdownMenuItem>
      <DropdownMenuItem onClick={onSendEmail} className="gap-2.5 text-xs">
        <Mail size={12} className="text-muted-foreground" /> Send mail
      </DropdownMenuItem>
      <DropdownMenuSeparator />
      <DropdownMenuItem onClick={onResetPassword} className="gap-2.5 text-xs">
        <Mail size={12} className="text-muted-foreground" /> Send password reset
      </DropdownMenuItem>
      <DropdownMenuItem onClick={onForceLogout} className="gap-2.5 text-xs">
        <LogOut size={12} className="text-muted-foreground" /> Force logout
      </DropdownMenuItem>
      {user.totp_enabled && (
        <DropdownMenuItem onClick={onResetMfa} className="gap-2.5 text-xs">
          <ShieldOff size={12} className="text-muted-foreground" /> Reset 2FA / MFA
        </DropdownMenuItem>
      )}
      <DropdownMenuSeparator />
      <DropdownMenuItem onClick={onDelete} className="gap-2.5 text-xs text-destructive focus:text-destructive focus:bg-destructive/10">
        <Trash2 size={12} /> Delete user
      </DropdownMenuItem>
    </DropdownMenuContent>
  </DropdownMenu>
)

// ── Page ──────────────────────────────────────────────────────────────────────
export const UserManagementPage: React.FC = () => {
  const [users, setUsers] = useState<UserOut[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [roleFilter, setRoleFilter] = useState<UserRole | 'all'>('all')
  const [actionLoading, setActionLoading] = useState<number | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<UserOut | null>(null)
  const [detailTarget, setDetailTarget] = useState<UserOut | null>(null)
  const [emailTarget, setEmailTarget] = useState<UserOut | null>(null)
  const [showAddModal, setShowAddModal] = useState(false)

  const fetchUsers = useCallback(() => {
    setLoading(true)
    adminApi.users()
      .then(setUsers)
      .catch(err => {
        if (err instanceof ApiError) setError(err.message)
        else setError('Failed to load users.')
      })
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { fetchUsers() }, [fetchUsers])

  const filtered = useMemo(() => {
    return users.filter(u => {
      const matchSearch =
        (u.name ?? '').toLowerCase().includes(search.toLowerCase()) ||
        u.email.toLowerCase().includes(search.toLowerCase())
      const matchRole = roleFilter === 'all' || u.role === roleFilter
      return matchSearch && matchRole
    })
  }, [users, search, roleFilter])

  const showSuccess = (msg: string) => {
    setSuccess(msg)
    setTimeout(() => setSuccess(null), 3500)
  }

  const handleRoleChange = async (userId: number, newRole: string) => {
    setActionLoading(userId)
    try {
      const updated = await adminApi.updateRole(userId, newRole)
      setUsers(prev => prev.map(u => u.id === userId ? updated : u))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to update role.')
    } finally {
      setActionLoading(null)
    }
  }

  const handleDeleteConfirm = async () => {
    if (!deleteTarget) return
    setActionLoading(deleteTarget.id)
    try {
      await adminApi.deleteUser(deleteTarget.id)
      setUsers(prev => prev.filter(u => u.id !== deleteTarget.id))
      showSuccess(`${deleteTarget.name ?? deleteTarget.email} has been deleted.`)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to delete user.')
    } finally {
      setActionLoading(null)
      setDeleteTarget(null)
    }
  }

  const handleResetPassword = async (user: UserOut) => {
    try {
      await adminApi.sendPasswordReset(user.email)
      showSuccess(`Password reset email sent to ${user.email}.`)
    } catch {
      setError('Failed to send password reset email.')
    }
  }

  const handleForceLogout = async (user: UserOut) => {
    setActionLoading(user.id)
    try {
      await adminApi.forceLogout(user.id)
      showSuccess(`All sessions revoked for ${user.name ?? user.email}. They will need to log in again.`)
    } catch {
      setError('Failed to revoke sessions.')
    } finally {
      setActionLoading(null)
    }
  }

  const handleResetMfa = async (user: UserOut) => {
    setActionLoading(user.id)
    try {
      await adminApi.resetUserMfa(user.id)
      setUsers(prev => prev.map(u => u.id === user.id ? { ...u, totp_enabled: false } : u))
      showSuccess(`2FA has been disabled for ${user.name ?? user.email}.`)
    } catch {
      setError('Failed to reset 2FA.')
    } finally {
      setActionLoading(null)
    }
  }

  const totalUsers = users.length
  const appOwners = users.filter(u => u.role === 'app_owner').length
  const admins = users.filter(u => u.role === 'admin').length
  const endUsers = users.filter(u => u.role === 'end_user').length

  return (
    <div className="flex flex-col gap-5 p-6">
      {/* Modals */}
      {deleteTarget && (
        <DeleteModal
          user={deleteTarget}
          onConfirm={handleDeleteConfirm}
          onCancel={() => setDeleteTarget(null)}
          loading={actionLoading === deleteTarget.id}
        />
      )}
      {detailTarget && (
        <UserDetailModal
          user={detailTarget}
          onClose={() => setDetailTarget(null)}
        />
      )}
      {emailTarget && (
        <SendEmailModal
          user={emailTarget}
          onClose={() => setEmailTarget(null)}
        />
      )}
      {showAddModal && (
        <AddUserModal
          onCreated={u => setUsers(prev => [u, ...prev])}
          onClose={() => setShowAddModal(false)}
        />
      )}

      {/* Stats */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {[
          { label: 'Total Users', value: totalUsers },
          { label: 'End Users', value: endUsers },
          { label: 'App Owners', value: appOwners },
          { label: 'Admins', value: admins },
        ].map(s => (
          <Card key={s.label}>
            <CardContent className="p-4">
              <p className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">{s.label}</p>
              <p className="mt-1 font-mono text-2xl font-bold leading-none text-foreground">{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {error && (
        <div className="flex items-center justify-between rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
          {error}
          <button onClick={() => setError(null)}><X size={12} /></button>
        </div>
      )}
      {success && (
        <div className="flex items-center justify-between rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-600 dark:text-emerald-400">
          {success}
          <button onClick={() => setSuccess(null)}><X size={12} /></button>
        </div>
      )}

      {/* Users table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <CardTitle className="text-sm font-semibold">Platform Users</CardTitle>
              <CardDescription className="text-xs">Manage accounts, roles and access</CardDescription>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Input
                placeholder="Search users…"
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="h-7 w-40 text-xs"
              />
              <Select value={roleFilter} onValueChange={val => setRoleFilter(val as UserRole | 'all')}>
                <SelectTrigger size="sm" className="h-7 w-[110px] font-mono text-[11px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All roles</SelectItem>
                  <SelectItem value="end_user">End User</SelectItem>
                  <SelectItem value="app_owner">App Owner</SelectItem>
                  <SelectItem value="admin">Admin</SelectItem>
                </SelectContent>
              </Select>
              <Button size="sm" className="h-7 gap-1.5 text-xs" variant="outline" onClick={fetchUsers} disabled={loading}>
                <RefreshCw size={11} className={loading ? 'animate-spin' : ''} /> Refresh
              </Button>
              <Button size="sm" className="h-7 gap-1.5 text-xs" onClick={() => setShowAddModal(true)}>
                <UserPlus size={12} /> Add User
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <span role="status" aria-label="Loading users"
                className="h-5 w-5 animate-spin rounded-full border-2 border-foreground border-t-transparent" />
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center gap-2 py-12 text-center">
              <Users size={28} className="text-muted-foreground/30" />
              <p className="text-sm text-muted-foreground">No users match your filters</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border">
                    <th className="bg-muted/30 px-4 py-2.5 text-left font-mono text-[10px] uppercase tracking-widest text-muted-foreground">User</th>
                    <th className="bg-muted/30 px-4 py-2.5 text-left font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Role</th>
                    <th className="bg-muted/30 px-4 py-2.5 text-left font-mono text-[10px] uppercase tracking-widest text-muted-foreground">2FA</th>
                    <th className="bg-muted/30 px-4 py-2.5 text-left font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Joined</th>
                    <th className="bg-muted/30 px-4 py-2.5 text-right font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(u => {
                    const name = u.name ?? u.email
                    const initials = name.trim().split(/\s+/).map(w => w[0]).join('').slice(0, 2).toUpperCase()
                    const busy = actionLoading === u.id
                    return (
                      <tr key={u.id} className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2.5">
                            <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-foreground font-mono text-[10px] font-bold text-background">
                              {initials}
                            </div>
                            <div className="min-w-0">
                              <p className="font-medium text-foreground truncate">{name}</p>
                              <p className="font-mono text-[10px] text-muted-foreground/60 truncate">{u.email}</p>
                            </div>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <Select value={u.role} onValueChange={val => handleRoleChange(u.id, val)} disabled={busy}>
                            <SelectTrigger size="sm" className={roleTriggerClass(u.role)}>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="end_user">End User</SelectItem>
                              <SelectItem value="app_owner">App Owner</SelectItem>
                              <SelectItem value="admin">Admin</SelectItem>
                            </SelectContent>
                          </Select>
                        </td>
                        <td className="px-4 py-3">
                          {u.totp_enabled
                            ? <span className="inline-flex items-center gap-1 font-mono text-[10px] text-emerald-500">● On</span>
                            : <span className="font-mono text-[10px] text-muted-foreground">Off</span>}
                        </td>
                        <td className="px-4 py-3 font-mono text-[10px] text-muted-foreground whitespace-nowrap">
                          {formatDateTime(u.created_at)}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center justify-end gap-1">
                            {busy ? (
                              <span role="status" aria-label="Processing"
                                className="h-4 w-4 animate-spin rounded-full border-2 border-foreground border-t-transparent inline-block" />
                            ) : (
                              <>
                                <Button
                                  variant="ghost" size="icon"
                                  className="h-7 w-7 text-destructive hover:bg-destructive/10 hover:text-destructive"
                                  title="Delete user"
                                  onClick={() => setDeleteTarget(u)}
                                >
                                  <Trash2 size={13} />
                                </Button>
                                <UserMenu
                                  user={u}
                                  onViewDetails={() => setDetailTarget(u)}
                                  onSendEmail={() => setEmailTarget(u)}
                                  onResetPassword={() => handleResetPassword(u)}
                                  onForceLogout={() => handleForceLogout(u)}
                                  onResetMfa={() => handleResetMfa(u)}
                                  onDelete={() => setDeleteTarget(u)}
                                />
                              </>
                            )}
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
