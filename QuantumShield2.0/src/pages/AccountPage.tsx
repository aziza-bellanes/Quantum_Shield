import React, { useState, useEffect, useRef } from 'react'
import { z } from 'zod'
import {
  User, Mail, Lock, Bell, Shield, Save, KeyRound, Eye, EyeOff, Copy, RefreshCw,
  Phone, Calendar, MapPin, FileText, CheckCircle, XCircle, QrCode, LocateFixed,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Separator } from '../components/ui/separator'
import { Calendar as CalendarPicker } from '../components/ui/calendar'
import { Popover, PopoverContent, PopoverTrigger } from '../components/ui/popover'
import { useAuth } from '../context/AuthContext'
import { roleLabel } from '../lib/utils'
import { profileApi, appsApi, ApiError } from '../lib/api'
import type { SessionOut } from '../lib/api'

function formatDateInput(date: Date): string {
  const year = date.getFullYear()
  const month = String(date.getMonth() + 1).padStart(2, '0')
  const day = String(date.getDate()).padStart(2, '0')
  return `${year}-${month}-${day}`
}

function formatDateLabel(value?: string | null): string {
  if (!value) return 'Pick a date'
  const parsed = new Date(`${value}T00:00:00`)
  if (Number.isNaN(parsed.getTime())) return 'Pick a date'
  return parsed.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  })
}

function formatDateTime(value?: string | null): string {
  if (!value) return '—'
  // If the backend returns UTC without a timezone suffix (e.g. "2026-04-15T10:30:00"),
  // JavaScript would parse it as local time — wrong. Append 'Z' to force UTC parsing.
  const normalized =
    value.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(value) ? value : value + 'Z'
  const parsed = new Date(normalized)
  if (Number.isNaN(parsed.getTime())) return '—'
  return parsed.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

// ── Schemas ───────────────────────────────────────────────────────────────────
const profileSchema = z.object({
  name:        z.string().min(2, 'Name must be at least 2 characters').max(64),
  email:       z.string().email('Please enter a valid email address'),
  company:     z.string().max(64, 'Company name too long').optional(),
  phone:       z.string().max(20, 'Phone number too long').optional(),
  dateOfBirth: z.string().optional(),
  location:    z.string().max(100, 'Location too long').optional(),
  bio:         z.string().max(500, 'Bio must be under 500 characters').optional(),
})

const passwordSchema = z.object({
  current: z.string().min(1, 'Current password is required'),
  next: z
    .string()
    .min(8, 'Must be at least 8 characters')
    .regex(/[A-Z]/, 'Must contain an uppercase letter')
    .regex(/[0-9]/, 'Must contain a number'),
  confirm: z.string().min(1, 'Please confirm your new password'),
}).refine(d => d.next === d.confirm, {
  message: 'Passwords do not match',
  path: ['confirm'],
})

type ProfileForm = z.infer<typeof profileSchema>
type PasswordForm = z.infer<typeof passwordSchema>
type ProfileErrors = Partial<Record<keyof ProfileForm, string>>
type PasswordErrors = Partial<Record<keyof PasswordForm, string>>

// ── FieldError ────────────────────────────────────────────────────────────────
const FieldError: React.FC<{ msg?: string }> = ({ msg }) =>
  msg ? <p className="mt-1 text-[11px] text-destructive">{msg}</p> : null

// ── Section wrapper ───────────────────────────────────────────────────────────
const Section: React.FC<{ icon: React.ReactNode; title: string; description: string; children: React.ReactNode }> = ({
  icon, title, description, children,
}) => (
  <Card>
    <CardHeader>
      <div className="flex items-center gap-2.5">
        <span className="text-muted-foreground">{icon}</span>
        <div>
          <CardTitle>{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </div>
      </div>
    </CardHeader>
    <Separator />
    <CardContent className="pt-5">{children}</CardContent>
  </Card>
)

// ── Profile form ──────────────────────────────────────────────────────────────
const ProfileSection: React.FC = () => {
  const { user, updateUser } = useAuth()
  const [form, setForm] = useState<ProfileForm>({
    name:        user?.name ?? '',
    email:       user?.email ?? '',
    company:     user?.company ?? '',
    phone:       user?.phone ?? '',
    dateOfBirth: user?.dateOfBirth ?? '',
    location:    user?.location ?? '',
    bio:         user?.bio ?? '',
  })
  const [errors, setErrors]   = useState<ProfileErrors>({})
  const [touched, setTouched] = useState<Partial<Record<keyof ProfileForm, boolean>>>({})
  const [saved, setSaved]     = useState(false)
  const [saving, setSaving]   = useState(false)
  const [serverError, setServerError] = useState('')
  const [detectingLocation, setDetectingLocation] = useState(false)
  const [locationError, setLocationError] = useState('')

  const validate = (d: ProfileForm): ProfileErrors => {
    const r = profileSchema.safeParse(d)
    if (r.success) return {}
    return r.error.issues.reduce<ProfileErrors>((a, i) => {
      const k = i.path[0] as keyof ProfileForm; if (!a[k]) a[k] = i.message; return a
    }, {})
  }

  const handleChange = (f: keyof ProfileForm) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const next = { ...form, [f]: e.target.value }
    setForm(next)
    if (touched[f]) setErrors(validate(next))
  }

  const handleBlur = (f: keyof ProfileForm) => () => {
    setTouched(t => ({ ...t, [f]: true })); setErrors(validate(form))
  }

  const handlePickDate = (date: Date | undefined) => {
    const next = { ...form, dateOfBirth: date ? formatDateInput(date) : '' }
    setForm(next)
    if (touched.dateOfBirth) setErrors(validate(next))
  }

  const handleDetectLocation = () => {
    if (!navigator.geolocation) {
      setLocationError('Geolocation is not supported by this browser.')
      return
    }
    setDetectingLocation(true)
    setLocationError('')
    navigator.geolocation.getCurrentPosition(
      ({ coords }) => {
        const next = {
          ...form,
          location: `${coords.latitude.toFixed(4)}, ${coords.longitude.toFixed(4)}`,
        }
        setForm(next)
        setTouched(t => ({ ...t, location: true }))
        setErrors(validate(next))
        setDetectingLocation(false)
      },
      () => {
        setLocationError('Unable to access your location. Check browser permissions.')
        setDetectingLocation(false)
      },
      { enableHighAccuracy: false, timeout: 10000, maximumAge: 300000 }
    )
  }

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()
    const allT = Object.fromEntries(Object.keys(form).map(k => [k, true])) as Record<keyof ProfileForm, boolean>
    setTouched(allT)
    const errs = validate(form)
    setErrors(errs)
    if (Object.keys(errs).length > 0) return

    setSaving(true)
    setServerError('')
    try {
      const updated = await profileApi.update(
        form.name,
        form.email,
        form.company,
        form.phone,
        form.dateOfBirth,
        form.location,
        form.bio,
      )
      updateUser({
        name:        updated.name ?? form.name,
        email:       updated.email,
        company:     updated.company ?? null,
        phone:       updated.phone ?? null,
        dateOfBirth: updated.date_of_birth ?? null,
        location:    updated.location ?? null,
        bio:         updated.bio ?? null,
      })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (err) {
      setServerError(err instanceof ApiError ? err.message : 'Failed to save profile')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Section icon={<User size={16} />} title="Profile" description="Update your personal information">
      <form onSubmit={handleSave} noValidate className="flex flex-col gap-4">
        <div className="flex items-center gap-4 mb-2">
          <div className="flex h-14 w-14 items-center justify-center rounded-full bg-foreground font-mono text-xl font-bold text-background">
            {user?.initials ?? '??'}
          </div>
          <div>
            <p className="text-sm font-medium text-foreground">{user?.name ?? ''}</p>
            <p className="text-xs text-muted-foreground">{user ? roleLabel(user.role) : ''}</p>
          </div>
        </div>
        <Separator />
        {serverError && <p className="text-[11px] text-destructive">{serverError}</p>}

        <div className="grid gap-4 sm:grid-cols-2">
          {/* Name */}
          <div>
            <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Full Name</label>
            <Input value={form.name} onChange={handleChange('name')} onBlur={handleBlur('name')} icon={<User size={13} />} className={errors.name && touched.name ? 'border-destructive' : ''} />
            <FieldError msg={touched.name ? errors.name : undefined} />
          </div>

          {/* Email */}
          <div>
            <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Email Address</label>
            <Input type="email" value={form.email} onChange={handleChange('email')} onBlur={handleBlur('email')} icon={<Mail size={13} />} className={errors.email && touched.email ? 'border-destructive' : ''} />
            <FieldError msg={touched.email ? errors.email : undefined} />
          </div>

          {/* Company */}
          <div>
            <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Company (optional)</label>
            <Input placeholder="Mertilly Corp" value={form.company ?? ''} onChange={handleChange('company')} onBlur={handleBlur('company')} className={errors.company && touched.company ? 'border-destructive' : ''} />
            <FieldError msg={touched.company ? errors.company : undefined} />
          </div>

          {/* Phone */}
          <div>
            <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Phone (optional)</label>
            <Input type="tel" placeholder="+216 12 345 678" value={form.phone ?? ''} onChange={handleChange('phone')} onBlur={handleBlur('phone')} icon={<Phone size={13} />} className={errors.phone && touched.phone ? 'border-destructive' : ''} />
            <FieldError msg={touched.phone ? errors.phone : undefined} />
          </div>

          {/* Date of birth */}
          <div>
            <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Date of Birth (optional)</label>
            <Popover>
              <PopoverTrigger asChild>
                <Button
                  type="button"
                  variant="outline"
                  className="h-8 w-full justify-start gap-2 text-left text-xs font-normal"
                >
                  <Calendar size={13} className="text-muted-foreground" />
                  {formatDateLabel(form.dateOfBirth)}
                </Button>
              </PopoverTrigger>
              <PopoverContent className="w-auto p-0" align="start">
                <CalendarPicker
                  mode="single"
                  selected={form.dateOfBirth ? new Date(`${form.dateOfBirth}T00:00:00`) : undefined}
                  onSelect={handlePickDate}
                  captionLayout="dropdown"
                  startMonth={new Date(1940, 0)}
                  endMonth={new Date()}
                />
                <div className="border-t border-border p-2">
                  <Button type="button" variant="ghost" size="sm" className="h-7 text-xs" onClick={() => handlePickDate(undefined)}>
                    Clear date
                  </Button>
                </div>
              </PopoverContent>
            </Popover>
          </div>

          {/* Location */}
          <div>
            <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Location (optional)</label>
            <div className="flex items-center gap-2">
              <Input placeholder="Manouba, Tunisia" value={form.location ?? ''} onChange={handleChange('location')} onBlur={handleBlur('location')} icon={<MapPin size={13} />} className={errors.location && touched.location ? 'border-destructive' : ''} />
              <Button
                type="button"
                variant="outline"
                size="icon"
                className="h-8 w-8 shrink-0"
                onClick={handleDetectLocation}
                disabled={detectingLocation}
                title="Use current location"
              >
                {detectingLocation
                  ? <span aria-hidden="true" className="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent" />
                  : <LocateFixed size={13} />}
              </Button>
            </div>
            <FieldError msg={touched.location ? errors.location : undefined} />
            {locationError && <p className="mt-1 text-[11px] text-destructive">{locationError}</p>}
          </div>

          {/* Bio */}
          <div className="sm:col-span-2">
            <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Bio (optional)</label>
            <textarea
              placeholder="Tell us a little about yourself…"
              value={form.bio ?? ''}
              onChange={handleChange('bio')}
              onBlur={handleBlur('bio')}
              rows={3}
              className={`flex w-full resize-none rounded-md border border-input bg-background px-3 py-2 text-xs text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${errors.bio && touched.bio ? 'border-destructive' : ''}`}
            />
            <div className="mt-0.5 flex items-center justify-between">
              <FieldError msg={touched.bio ? errors.bio : undefined} />
              <span className="font-mono text-[10px] text-muted-foreground/60">{(form.bio ?? '').length}/500</span>
            </div>
          </div>
        </div>

        <div className="flex justify-end">
          <Button type="submit" size="sm" className="gap-2" disabled={saving} aria-busy={saving}>
            {saving
              ? <><span aria-hidden="true" className="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent" /> Saving…</>
              : <><Save size={13} /> {saved ? 'Saved!' : 'Save Changes'}</>}
          </Button>
        </div>
      </form>
    </Section>
  )
}

// ── Password form ─────────────────────────────────────────────────────────────
const PasswordSection: React.FC = () => {
  const [form, setForm]       = useState<PasswordForm>({ current: '', next: '', confirm: '' })
  const [errors, setErrors]   = useState<PasswordErrors>({})
  const [touched, setTouched] = useState<Partial<Record<keyof PasswordForm, boolean>>>({})
  const [saved, setSaved]     = useState(false)
  const [saving, setSaving]   = useState(false)
  const [serverError, setServerError] = useState('')
  const [showCurrent, setShowCurrent] = useState(false)
  const [showNext, setShowNext]       = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)

  const validate = (d: PasswordForm): PasswordErrors => {
    const r = passwordSchema.safeParse(d)
    if (r.success) return {}
    return r.error.issues.reduce<PasswordErrors>((a, i) => {
      const k = i.path[0] as keyof PasswordForm; if (!a[k]) a[k] = i.message; return a
    }, {})
  }

  const handleChange = (f: keyof PasswordForm) => (e: React.ChangeEvent<HTMLInputElement>) => {
    const next = { ...form, [f]: e.target.value }; setForm(next)
    if (touched[f]) setErrors(validate(next))
  }

  const handleBlur = (f: keyof PasswordForm) => () => {
    setTouched(t => ({ ...t, [f]: true })); setErrors(validate(form))
  }

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()
    const allT: Record<keyof PasswordForm, boolean> = { current: true, next: true, confirm: true }
    setTouched(allT); const errs = validate(form); setErrors(errs)
    if (Object.keys(errs).length > 0) return

    setSaving(true)
    setServerError('')
    try {
      await profileApi.changePassword(form.current, form.next)
      setSaved(true)
      setForm({ current: '', next: '', confirm: '' })
      setTouched({})
      setShowCurrent(false); setShowNext(false); setShowConfirm(false)
      setTimeout(() => setSaved(false), 2000)
    } catch (err) {
      setServerError(err instanceof ApiError ? err.message : 'Failed to update password')
    } finally {
      setSaving(false)
    }
  }

  const pwField = (
    f: keyof PasswordForm,
    label: string,
    ac: string,
    show: boolean,
    setShow: React.Dispatch<React.SetStateAction<boolean>>,
  ) => (
    <div key={f}>
      <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">{label}</label>
      <div className="relative">
        <Input
          type={show ? 'text' : 'password'}
          placeholder="••••••••"
          value={form[f]}
          onChange={handleChange(f)}
          onBlur={handleBlur(f)}
          icon={<KeyRound size={13} />}
          autoComplete={ac}
          className={`pr-9 ${errors[f] && touched[f] ? 'border-destructive' : ''}`}
        />
        <button
          type="button"
          tabIndex={-1}
          onClick={() => setShow(v => !v)}
          className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
          aria-label={show ? 'Hide password' : 'Show password'}
        >
          {show ? <EyeOff size={14} /> : <Eye size={14} />}
        </button>
      </div>
      <FieldError msg={touched[f] ? errors[f] : undefined} />
    </div>
  )

  return (
    <Section icon={<Lock size={16} />} title="Password" description="Change your account password">
      <form onSubmit={handleSave} noValidate className="flex flex-col gap-4">
        {serverError && <p className="text-[11px] text-destructive">{serverError}</p>}
        {pwField('current', 'Current password', 'current-password', showCurrent, setShowCurrent)}
        {pwField('next',    'New password',     'new-password',     showNext,    setShowNext)}
        {pwField('confirm', 'Confirm new password', 'new-password', showConfirm, setShowConfirm)}
        <div className="flex justify-end">
          <Button type="submit" size="sm" className="gap-2" disabled={saving} aria-busy={saving}>
            {saving
              ? <><span aria-hidden="true" className="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent" /> Updating…</>
              : <><Save size={13} /> {saved ? 'Password Updated!' : 'Update Password'}</>}
          </Button>
        </div>
      </form>
    </Section>
  )
}

// ── Notifications section ─────────────────────────────────────────────────────
const NotifSection: React.FC = () => {
  const [prefs, setPrefs] = useState({ email: true, security: true, reports: false, updates: true })
  const [loading, setLoading] = useState(true)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    profileApi.getPreferences()
      .then(p => setPrefs({ email: p.email_notifications, security: p.security_alerts, reports: p.weekly_reports, updates: p.product_updates }))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const toggle = (k: keyof typeof prefs) => {
    const next = { ...prefs, [k]: !prefs[k] }
    setPrefs(next)
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => {
      profileApi.updatePreferences({
        email_notifications: next.email,
        security_alerts: next.security,
        weekly_reports: next.reports,
        product_updates: next.updates,
      }).catch(() => {})
    }, 600)
  }

  const items = [
    { k: 'email' as const,    label: 'Email notifications', sub: 'Receive updates via email' },
    { k: 'security' as const, label: 'Security alerts',     sub: 'Alerts for high-risk findings' },
    { k: 'reports' as const,  label: 'Weekly reports',      sub: 'Summary of your application portfolio' },
    { k: 'updates' as const,  label: 'Product updates',     sub: 'New features and platform announcements' },
  ]

  return (
    <Section icon={<Bell size={16} />} title="Notifications" description="Control what emails and alerts you receive">
      <div className="flex flex-col gap-0">
        {loading
          ? <p className="text-xs text-muted-foreground">Loading…</p>
          : items.map(({ k, label, sub }, i) => (
            <div key={k}>
              {i > 0 && <Separator className="my-3" />}
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-foreground">{label}</p>
                  <p className="text-xs text-muted-foreground">{sub}</p>
                </div>
                <button
                  onClick={() => toggle(k)}
                  className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors duration-200 ${prefs[k] ? 'bg-primary' : 'bg-muted-foreground/30'}`}
                  role="switch" aria-checked={prefs[k]}
                >
                  <span className={`inline-block h-3.5 w-3.5 rounded-full bg-white shadow transition-transform duration-200 ${prefs[k] ? 'translate-x-4' : 'translate-x-0.5'}`} />
                </button>
              </div>
            </div>
          ))}
      </div>
    </Section>
  )
}

// ── API Key section (app_owner only) ─────────────────────────────────────────
const ApiKeySection: React.FC = () => {
  const [revealed, setRevealed]       = useState(false)
  const [copied, setCopied]           = useState(false)
  const [regenerating, setRegenerating] = useState(false)
  const [key, setKey]                 = useState('')
  const [loading, setLoading]         = useState(true)

  useEffect(() => {
    profileApi.getApiKey()
      .then(k => setKey(k.key))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const handleCopy = () => {
    navigator.clipboard.writeText(key).catch(() => {})
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  const handleRegenerate = async () => {
    setRegenerating(true)
    try {
      const k = await profileApi.regenerateApiKey()
      setKey(k.key)
      setRevealed(true)
    } catch { /* ignore */ }
    finally { setRegenerating(false) }
  }

  const masked = key ? key.slice(0, 11) + '••••••••••••••••' : '••••••••••••••••••••••••••'

  return (
    <Section icon={<KeyRound size={16} />} title="API Access" description="Manage your programmatic API credentials">
      <div className="flex flex-col gap-4">
        {loading ? (
          <p className="text-xs text-muted-foreground">Loading…</p>
        ) : (
          <>
            <div>
              <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Production API Key</label>
              <div className="flex items-center gap-2">
                <div className="flex-1 rounded-lg border border-input bg-muted/20 px-3 py-1.5 font-mono text-xs text-foreground">
                  {revealed ? key : masked}
                </div>
                <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0" onClick={() => setRevealed(r => !r)} title={revealed ? 'Hide' : 'Reveal'}>
                  {revealed ? <EyeOff size={13} /> : <Eye size={13} />}
                </Button>
                <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0" onClick={handleCopy} title="Copy">
                  <Copy size={13} />
                </Button>
              </div>
              {copied && <p className="mt-1 font-mono text-[10px] text-emerald-500">Copied to clipboard</p>}
            </div>
            <div>
              <Button variant="outline" size="sm" className="gap-2 h-8 text-xs" onClick={handleRegenerate} disabled={regenerating} aria-busy={regenerating}>
                {regenerating
                  ? <><span aria-hidden="true" className="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent" /> Regenerating…</>
                  : <><RefreshCw size={12} /> Regenerate Key</>}
              </Button>
              <p className="mt-1.5 text-[11px] text-muted-foreground/60">Regenerating invalidates your current key immediately.</p>
            </div>
          </>
        )}
      </div>
    </Section>
  )
}

// ── Plan card (right panel) ───────────────────────────────────────────────────
const PlanCard: React.FC = () => {
  const { user } = useAuth()
  const [appsCount, setAppsCount] = useState<number | null>(null)
  const [lastLogin, setLastLogin] = useState<string>('—')

  useEffect(() => {
    if (!user) return
    if (user.role === 'app_owner' || user.role === 'admin') {
      const uid = Number.parseInt(user.id, 10)
      appsApi.list('', 0, 10000)
        .then(all => setAppsCount(all.filter(a => a.owner_id === uid).length))
        .catch(() => setAppsCount(0))
    } else {
      appsApi.stats()
        .then(s => setAppsCount(s.total_apps))
        .catch(() => setAppsCount(0))
    }

    profileApi.getSessions()
      .then((sessions) => {
        const mostRecent = sessions[0]
        setLastLogin(formatDateTime(mostRecent?.last_seen_at))
      })
      .catch(() => setLastLogin('—'))
  }, [user])

  // Dynamic account completion
  const completionPct = user ? (() => {
    const textFields = [user.name, user.email, user.company, user.phone, user.dateOfBirth, user.location, user.bio]
    const filled = textFields.filter(v => v && String(v).trim() !== '').length + (user.totpEnabled ? 1 : 0)
    return Math.round((filled / 8) * 100)
  })() : 0

  // Use the full IANA timezone string (e.g. "Europe/Paris") with underscores replaced.
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone ?? ''
  const region = user?.location?.trim() || tz.replaceAll('_', ' ') || '—'

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2.5">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-foreground font-mono text-sm font-bold text-background">
            {user?.initials ?? '??'}
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-semibold text-foreground">{user?.name ?? ''}</p>
            <p className="text-xs text-muted-foreground">{user?.email ?? ''}</p>
          </div>
        </div>
      </CardHeader>
      <Separator />
      <CardContent className="pt-4">
        <div className="flex flex-col gap-3">
          {/* Account completion progress */}
          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Profile completion</span>
              <span className="font-mono text-xs font-semibold text-foreground">{completionPct}%</span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
              <div
                className="h-full rounded-full bg-primary transition-all duration-500"
                style={{ width: `${completionPct}%` }}
              />
            </div>
          </div>
          <Separator />
          {/* Apps monitored */}
          <div className="flex items-center justify-between">
            <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Apps monitored</span>
            <span className="text-xs font-semibold text-foreground">
              {appsCount === null ? '…' : appsCount}
            </span>
          </div>
          <Separator />
          {[
            { label: 'Role',         value: user ? roleLabel(user.role) : '' },
            { label: 'Member since', value: user?.joinDate ?? '' },
            { label: 'Region',       value: region },
            { label: 'Last login',   value: lastLogin },
          ].map(r => (
            <div key={r.label} className="flex items-center justify-between">
              <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{r.label}</span>
              <span className="text-xs text-foreground">{r.value}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}

// ── Security card ─────────────────────────────────────────────────────────────
type TwoFaStep = 'idle' | 'loading_setup' | 'scan' | 'verifying' | 'disable_confirm' | 'disabling'

const SecurityCard: React.FC = () => {
  const { user, updateUser } = useAuth()
  const [sessions, setSessions]           = useState<SessionOut[]>([])
  const [loadingSessions, setLoadingSessions] = useState(true)
  const [revoking, setRevoking]           = useState<number | 'all' | null>(null)

  // 2FA state
  const [twoFaStep, setTwoFaStep] = useState<TwoFaStep>('idle')
  const [qrDataUrl, setQrDataUrl] = useState('')
  const [twoFaCode, setTwoFaCode] = useState('')
  const [twoFaError, setTwoFaError] = useState('')

  useEffect(() => {
    profileApi.getSessions()
      .then(setSessions)
      .catch(() => setSessions([]))
      .finally(() => setLoadingSessions(false))
  }, [])

  const handleRevokeAll = async () => {
    setRevoking('all')
    try {
      await profileApi.revokeAllSessions()
      setSessions([])
    } catch { /* ignore */ }
    finally { setRevoking(null) }
  }

  const handleRevoke = async (id: number) => {
    setRevoking(id)
    try {
      await profileApi.revokeSession(id)
      setSessions(s => s.filter(x => x.id !== id))
    } catch { /* ignore */ }
    finally { setRevoking(null) }
  }

  const handleSetup2fa = async () => {
    setTwoFaStep('loading_setup')
    setTwoFaError('')
    try {
      const data = await profileApi.setup2fa()
      setQrDataUrl(data.qr_data_url)
      setTwoFaStep('scan')
    } catch {
      setTwoFaError('Failed to start 2FA setup. Please try again.')
      setTwoFaStep('idle')
    }
  }

  const handleVerify2fa = async () => {
    if (!twoFaCode.trim()) { setTwoFaError('Please enter the 6-digit code.'); return }
    setTwoFaStep('verifying')
    setTwoFaError('')
    try {
      const updated = await profileApi.verify2fa(twoFaCode)
      updateUser({ totpEnabled: updated.totp_enabled })
      setTwoFaStep('idle')
      setTwoFaCode('')
    } catch {
      setTwoFaError('Invalid code. Please try again.')
      setTwoFaStep('scan')
    }
  }

  const handleDisable2fa = async () => {
    if (!twoFaCode.trim()) { setTwoFaError('Please enter the 6-digit code.'); return }
    setTwoFaStep('disabling')
    setTwoFaError('')
    try {
      const updated = await profileApi.disable2fa(twoFaCode)
      updateUser({ totpEnabled: updated.totp_enabled })
      setTwoFaStep('idle')
      setTwoFaCode('')
    } catch {
      setTwoFaError('Invalid code. 2FA was not disabled.')
      setTwoFaStep('disable_confirm')
    }
  }

  const cancelTwoFa = () => {
    setTwoFaStep('idle')
    setTwoFaCode('')
    setTwoFaError('')
    setQrDataUrl('')
  }

  const isBusy = twoFaStep === 'loading_setup' || twoFaStep === 'verifying' || twoFaStep === 'disabling'
  const totpEnabled = user?.totpEnabled ?? false

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2.5">
          <span className="text-muted-foreground"><Shield size={16} /></span>
          <div>
            <CardTitle>Security</CardTitle>
            <CardDescription>Sessions & two-factor authentication</CardDescription>
          </div>
        </div>
      </CardHeader>
      <Separator />
      <CardContent className="pt-4">
        <div className="flex flex-col gap-4">

          {/* 2FA section */}
          <div className="flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-foreground">Two-factor auth</p>
                <p className="text-[11px] text-muted-foreground">
                  {totpEnabled
                    ? <span className="flex items-center gap-1 text-emerald-500"><CheckCircle size={11} /> Enabled via Google Authenticator</span>
                    : <span className="flex items-center gap-1 text-muted-foreground"><XCircle size={11} /> Not enabled</span>}
                </p>
              </div>
              {twoFaStep === 'idle' && (
                totpEnabled ? (
                  <Button variant="outline" size="sm" className="h-7 text-xs text-destructive border-destructive/40 hover:bg-destructive/10"
                    onClick={() => { setTwoFaStep('disable_confirm'); setTwoFaError('') }}>
                    Disable
                  </Button>
                ) : (
                  <Button variant="outline" size="sm" className="h-7 text-xs" onClick={handleSetup2fa} disabled={isBusy}>
                    <QrCode size={11} className="mr-1" /> Enable
                  </Button>
                )
              )}
              {twoFaStep !== 'idle' && (
                <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={cancelTwoFa} disabled={isBusy}>
                  Cancel
                </Button>
              )}
            </div>

            {/* Setup: loading */}
            {twoFaStep === 'loading_setup' && (
              <div role="status" aria-label="Generating QR code"
                className="flex items-center gap-2 rounded-lg border border-border/60 bg-muted/20 px-4 py-3">
                <span aria-hidden="true" className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" />
                <span className="text-xs text-muted-foreground">Generating QR code…</span>
              </div>
            )}

            {/* Setup: scan QR */}
            {twoFaStep === 'scan' && (
              <div className="rounded-lg border border-border/60 bg-muted/20 px-4 py-4 flex flex-col gap-3">
                <p className="text-xs font-medium text-foreground">Scan with Google Authenticator</p>
                <p className="text-[11px] text-muted-foreground leading-relaxed">
                  Open Google Authenticator (or any TOTP app), tap <strong>+</strong>, choose <strong>Scan QR code</strong>, then point your camera at the code below.
                </p>
                {qrDataUrl && (
                  <img src={qrDataUrl} alt="2FA QR code" className="h-36 w-36 rounded-lg border border-border bg-white p-1" />
                )}
                <div>
                  <label className="mb-1 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Enter 6-digit code</label>
                  <div className="flex gap-2">
                    <Input
                      type="text"
                      inputMode="numeric"
                      maxLength={6}
                      placeholder="000000"
                      value={twoFaCode}
                      onChange={e => setTwoFaCode(e.target.value.replace(/\D/g, ''))}
                      className="w-32 font-mono text-sm tracking-widest"
                    />
                    <Button size="sm" className="gap-1.5" onClick={handleVerify2fa} disabled={isBusy} aria-busy={isBusy}>
                      {twoFaStep === 'verifying'
                        ? <><span aria-hidden="true" className="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent" /> Verifying…</>
                        : 'Verify & Enable'}
                    </Button>
                  </div>
                  {twoFaError && <p className="mt-1 text-[11px] text-destructive">{twoFaError}</p>}
                </div>
              </div>
            )}

            {/* Disable: confirm with code */}
            {(twoFaStep === 'disable_confirm' || twoFaStep === 'disabling') && (
              <div className="rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-4 flex flex-col gap-3">
                <p className="text-xs font-medium text-foreground">Confirm with your authenticator code</p>
                <p className="text-[11px] text-muted-foreground">
                  Enter the current 6-digit code from your authenticator app to disable 2FA.
                </p>
                <div className="flex gap-2">
                  <Input
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    placeholder="000000"
                    value={twoFaCode}
                    onChange={e => setTwoFaCode(e.target.value.replace(/\D/g, ''))}
                    className="w-32 font-mono text-sm tracking-widest"
                  />
                  <Button size="sm" variant="destructive" className="gap-1.5" onClick={handleDisable2fa} disabled={isBusy} aria-busy={isBusy}>
                    {twoFaStep === 'disabling'
                      ? <><span aria-hidden="true" className="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent" /> Disabling…</>
                      : 'Disable 2FA'}
                  </Button>
                </div>
                {twoFaError && <p className="text-[11px] text-destructive">{twoFaError}</p>}
              </div>
            )}
          </div>

          <Separator />

          {/* Active sessions */}
          <div>
            <div className="mb-2 flex items-center justify-between">
              <p className="text-sm font-medium text-foreground">Active sessions</p>
              <Button
                variant="ghost"
                size="sm"
                className="h-7 text-xs text-destructive hover:text-destructive px-2"
                onClick={handleRevokeAll}
                disabled={revoking === 'all' || sessions.length === 0}
              >
                {revoking === 'all' ? 'Revoking…' : 'Revoke all'}
              </Button>
            </div>
            {loadingSessions ? (
              <p className="text-xs text-muted-foreground">Loading sessions…</p>
            ) : sessions.length === 0 ? (
              <p className="text-xs text-muted-foreground">No active sessions</p>
            ) : (
              sessions.map((s, i) => (
                <div key={s.id} className={`flex items-center justify-between rounded-md border border-border/60 px-3 py-2 ${i < sessions.length - 1 ? 'mb-2' : ''}`}>
                  <div>
                    <p className="text-xs font-medium text-foreground">{s.browser ?? 'Browser'} · {s.os ?? 'Unknown OS'}</p>
                    <p className="font-mono text-[10px] text-muted-foreground">{s.ip ?? '—'}</p>
                  </div>
                  {i === 0
                    ? <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-emerald-500">● Current</span>
                    : <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 text-[11px] px-2 text-muted-foreground hover:text-destructive"
                        onClick={() => handleRevoke(s.id)}
                        disabled={revoking === s.id}
                      >
                        {revoking === s.id ? '…' : 'Revoke'}
                      </Button>
                  }
                </div>
              ))
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

export const AccountPage: React.FC = () => {
  const { user } = useAuth()
  return (
    <div className="grid h-full grid-cols-1 gap-5 p-6 lg:grid-cols-[1fr_320px]">
      <div className="flex min-w-0 flex-col gap-5">
        <ProfileSection />
        <PasswordSection />
        {(user?.role === 'app_owner' || user?.role === 'admin') && <ApiKeySection />}
        <NotifSection />
      </div>

      <div className="flex flex-col gap-5 lg:sticky lg:top-6 lg:self-start">
        <PlanCard />
        <SecurityCard />
      </div>
    </div>
  )
}
