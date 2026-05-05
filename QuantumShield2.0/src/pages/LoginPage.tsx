import React, { useState, useEffect } from 'react'
import { z } from 'zod'
import { ArrowRight, ShieldCheck, Info, Lock, KeyRound, Eye, EyeOff, User, Briefcase } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { GoogleLogin } from '@react-oauth/google'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Separator } from '../components/ui/separator'
import { QuantumLogo } from '../components/ui/quantum-logo'
import { useAuth } from '../context/AuthContext'
import { ModeToggle } from '../components/mode-toggle'
import { authApi, profileApi } from '../lib/api'
import type { UserRole } from '../lib/types'

const loginSchema = z.object({
  email: z.string().min(1, 'Email is required').email('Please enter a valid email address'),
  password: z.string().min(1, 'Password is required'),
})

type LoginForm = z.infer<typeof loginSchema>
type FormErrors = Partial<Record<keyof LoginForm, string>>

const DEMO_USERS = [
  { role: 'End User', email: 'user@qs.io', password: 'User1234!' },
  { role: 'App Owner', email: 'owner@qs.io', password: 'Owner123!' },
  { role: 'Admin', email: 'admin@qs.io', password: 'Admin123!' },
]

const GITHUB_CLIENT_ID = (import.meta.env.VITE_GITHUB_CLIENT_ID as string | undefined) ?? ''
const GOOGLE_CLIENT_ID = (import.meta.env.VITE_GOOGLE_CLIENT_ID as string | undefined) ?? ''

const GoogleIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24">
    <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4" />
    <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
    <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05" />
    <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335" />
  </svg>
)

const GithubIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
  </svg>
)

const features = [
  'Post-quantum cryptography analysis',
  'Real-time TLS version monitoring',
  'Automated risk scoring & alerts',
  'Quantum-safe readiness reports',
]

const stats = [
  { value: '927+', label: 'Apps Analyzed' },
  { value: '31%', label: 'PQC Ready' },
  { value: '94%', label: 'Threat Detection Rate' },
]

const BrandPanel: React.FC = () => (
  <div className="relative hidden lg:flex lg:w-5/12 flex-col overflow-hidden"
    style={{ background: 'hsl(222,22%,7%)' }}>
    <div className="pointer-events-none absolute inset-0"
      style={{ backgroundImage: 'radial-gradient(circle, rgba(255,255,255,0.055) 1px, transparent 1px)', backgroundSize: '28px 28px' }} />
    <div className="pointer-events-none absolute -top-40 -left-20 h-[420px] w-[420px] rounded-full blur-3xl"
      style={{ background: 'radial-gradient(circle, rgba(59,130,246,0.13) 0%, transparent 70%)' }} />
    <div className="pointer-events-none absolute bottom-10 right-0 h-64 w-64 rounded-full blur-3xl"
      style={{ background: 'radial-gradient(circle, rgba(34,197,94,0.08) 0%, transparent 70%)' }} />

    <div className="relative flex h-full flex-col justify-between p-10 xl:p-12">
      <div className="flex items-center gap-3">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg ring-1 ring-white/15"
          style={{ background: 'rgba(255,255,255,0.08)' }}>
          <QuantumLogo size={18} className="text-white" />
        </div>
        <span className="text-sm font-semibold text-white/90">Quantum Shield</span>
      </div>

      <div>
        <h2 className="text-[2rem] font-bold leading-[1.15] tracking-tight text-white">
          Security built<br />for the{' '}
          <span style={{ background: 'linear-gradient(135deg,#60a5fa,#34d399)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            quantum era.
          </span>
        </h2>
        <p className="mt-4 text-sm leading-relaxed" style={{ color: 'rgba(255,255,255,0.45)' }}>
          Monitor application security posture, TLS compliance, and post-quantum
          cryptography readiness - all in one platform.
        </p>
        <ul className="mt-6 flex flex-col gap-2.5">
          {features.map(f => (
            <li key={f} className="flex items-center gap-2.5">
              <span className="flex h-[18px] w-[18px] shrink-0 items-center justify-center rounded-full"
                style={{ background: 'rgba(52,211,153,0.15)' }}>
                <ShieldCheck size={10} style={{ color: '#34d399' }} />
              </span>
              <span className="text-[13px]" style={{ color: 'rgba(255,255,255,0.55)' }}>{f}</span>
            </li>
          ))}
        </ul>
        <div className="mt-8 grid grid-cols-3 overflow-hidden rounded-xl"
          style={{ border: '1px solid rgba(255,255,255,0.07)' }}>
          {stats.map((s, i) => (
            <div key={s.label} className="flex flex-col gap-0.5 px-4 py-3"
              style={{ background: 'rgba(255,255,255,0.03)', borderRight: i < 2 ? '1px solid rgba(255,255,255,0.07)' : 'none' }}>
              <span className="font-mono text-lg font-bold text-white">{s.value}</span>
              <span className="font-mono text-[9px] uppercase tracking-widest" style={{ color: 'rgba(255,255,255,0.3)' }}>{s.label}</span>
            </div>
          ))}
        </div>
      </div>

      <div style={{ borderLeft: '2px solid rgba(255,255,255,0.1)', paddingLeft: 14 }}>
        <p className="text-xs italic" style={{ color: 'rgba(255,255,255,0.3)' }}>
          "The most professional security dashboard we've deployed enterprise-wide."
        </p>
        <p className="mt-1 font-mono text-[10px]" style={{ color: 'rgba(255,255,255,0.18)' }}>— Security Lead, Fortune 500</p>
      </div>
    </div>
  </div>
)

const FieldError: React.FC<{ msg?: string }> = ({ msg }) =>
  msg ? <p className="mt-1 text-[11px] text-destructive">{msg}</p> : null

// ── Role selection modal (shown after first-time OAuth sign-in) ───────────────
const RoleModal: React.FC<{
  onSelect: (role: UserRole) => void
  loading: boolean
}> = ({ onSelect, loading }) => (
  <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
    <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
    <div className="relative flex w-full max-w-md flex-col rounded-xl border border-border bg-background p-6 shadow-2xl">
      <h2 className="text-base font-semibold text-foreground">One last step</h2>
      <p className="mt-1 text-sm text-muted-foreground">
        How will you use QuantumShield? Choose the account type that best fits your needs.
      </p>
      <div className="mt-5 flex flex-col gap-3">
        <button
          type="button"
          disabled={loading}
          onClick={() => onSelect('end_user')}
          className="flex items-start gap-4 rounded-lg border border-border bg-muted/20 p-4 text-left transition-colors hover:border-foreground/40 hover:bg-muted/40 disabled:opacity-50"
        >
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-blue-500/10 border border-blue-500/20">
            <User size={16} className="text-blue-500" />
          </div>
          <div>
            <p className="text-sm font-semibold text-foreground">End User</p>
            <p className="mt-0.5 text-xs text-muted-foreground">Browse and monitor applications in the dataset. Best for security researchers and compliance teams.</p>
          </div>
        </button>
        <button
          type="button"
          disabled={loading}
          onClick={() => onSelect('app_owner')}
          className="flex items-start gap-4 rounded-lg border border-border bg-muted/20 p-4 text-left transition-colors hover:border-foreground/40 hover:bg-muted/40 disabled:opacity-50"
        >
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-violet-500/10 border border-violet-500/20">
            <Briefcase size={16} className="text-violet-500" />
          </div>
          <div>
            <p className="text-sm font-semibold text-foreground">App Owner</p>
            <p className="mt-0.5 text-xs text-muted-foreground">Submit and analyze your own applications. Get detailed TLS and PQC reports for apps you own.</p>
          </div>
        </button>
      </div>
      {loading && (
        <div role="status" aria-label="Saving your choice"
          className="mt-4 flex items-center justify-center gap-2 text-sm text-muted-foreground">
          <span aria-hidden="true" className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" />
          Saving your choice…
        </div>
      )}
    </div>
  </div>
)

// ── Google button — custom styled button over invisible GoogleLogin ───────────
const GoogleButton: React.FC<{
  onSuccess: (cr: { credential?: string }) => void
  onError: () => void
  text?: 'signin_with' | 'signup_with'
}> = ({ onSuccess, onError, text = 'signin_with' }) => (
  <div className="relative h-9">
    {/* Visible custom-styled button — pointer-events-none so clicks reach the overlay */}
    <Button
      variant="outline"
      type="button"
      className="pointer-events-none h-9 w-full gap-2.5 font-normal"
      tabIndex={-1}
      aria-hidden
    >
      <GoogleIcon />
      {text === 'signup_with' ? 'Continue with Google' : 'Continue with Google'}
    </Button>
    {/* Invisible GoogleLogin overlay — receives the actual clicks */}
    {GOOGLE_CLIENT_ID && (
      <div
        className="absolute inset-0 overflow-hidden"
        style={{ opacity: 0.001 }}
        aria-hidden
      >
        <GoogleLogin
          onSuccess={onSuccess}
          onError={onError}
          type="standard"
          theme="outline"
          size="large"
          width="340"
          text={text}
        />
      </div>
    )}
  </div>
)

export const LoginPage: React.FC = () => {
  const navigate = useNavigate()
  const { login, loginWithGoogle, updateUser } = useAuth()

  const [form, setForm] = useState<LoginForm>({ email: '', password: '' })
  const [errors, setErrors] = useState<FormErrors>({})
  const [touched, setTouched] = useState<Partial<Record<keyof LoginForm, boolean>>>({})
  const [remember, setRemember] = useState(true)
  const [loading, setLoading] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [showPassword, setShowPassword] = useState(false)
  const [twoFaStep, setTwoFaStep] = useState(false)
  const [totpCode, setTotpCode] = useState('')
  const [totpError, setTotpError] = useState<string | null>(null)
  const [forgotOpen, setForgotOpen] = useState(false)
  const [forgotEmail, setForgotEmail] = useState('')
  const [forgotStatus, setForgotStatus] = useState<'idle' | 'sending' | 'sent' | 'error'>('idle')
  const [forgotNeedsTotp, setForgotNeedsTotp] = useState(false)
  const [forgotTotpCode, setForgotTotpCode] = useState('')
  const [forgotTotpError, setForgotTotpError] = useState<string | null>(null)
  const [showRoleModal, setShowRoleModal] = useState(false)
  const [roleLoading, setRoleLoading] = useState(false)
  const [sessionExpired, setSessionExpired] = useState(false)

  // Show a banner if AuthContext flagged the previous session as expired
  useEffect(() => {
    if (sessionStorage.getItem('qs_session_expired') === '1') {
      sessionStorage.removeItem('qs_session_expired')
      setSessionExpired(true)
    }
  }, [])

  const validate = (data: LoginForm): FormErrors => {
    const result = loginSchema.safeParse(data)
    if (result.success) return {}
    return result.error.issues.reduce<FormErrors>((acc, issue) => {
      const key = issue.path[0] as keyof LoginForm
      if (!acc[key]) acc[key] = issue.message
      return acc
    }, {})
  }

  const handleChange = (field: keyof LoginForm) => (e: React.ChangeEvent<HTMLInputElement>) => {
    const next = { ...form, [field]: e.target.value }
    setForm(next)
    setFormError(null)
    if (touched[field]) setErrors(validate(next))
  }

  const handleBlur = (field: keyof LoginForm) => () => {
    setTouched(t => ({ ...t, [field]: true }))
    setErrors(validate(form))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (twoFaStep) {
      if (!totpCode || totpCode.length !== 6) { setTotpError('Enter the 6-digit code from your authenticator.'); return }
      setLoading(true)
      const result = await login(form.email, form.password, remember, totpCode)
      setLoading(false)
      if (result === 'ok') navigate('/dashboard')
      else if (result === 'invalid_credentials') setTotpError('Invalid 2FA code. Please try again.')
      else setTotpError('Something went wrong. Please try again.')
      return
    }

    setTouched({ email: true, password: true })
    const errs = validate(form)
    setErrors(errs)
    if (Object.keys(errs).length > 0) return
    setLoading(true)
    const result = await login(form.email, form.password, remember)
    setLoading(false)
    if (result === 'ok') navigate('/dashboard')
    else if (result === 'requires_2fa') setTwoFaStep(true)
    else if (result === 'invalid_credentials') setFormError('Invalid email or password.')
    else setFormError('Could not connect to the server. Is the backend running?')
  }

  const fillDemo = (email: string, password: string) => {
    setForm({ email, password })
    setErrors({})
    setFormError(null)
    setTouched({})
    setTwoFaStep(false)
    setTotpCode('')
  }

  const handleGoogleSuccess = async (credentialResponse: { credential?: string }) => {
    const credential = credentialResponse.credential
    if (!credential) {
      setFormError('Google sign-in did not return a token. Please try again.')
      return
    }
    const res = await loginWithGoogle(credential)
    if (res === 'ok') navigate('/dashboard')
    else if (res === 'ok_new') setShowRoleModal(true)
    else setFormError('Google sign-in failed. Please try again.')
  }

  const handleRoleSelect = async (role: UserRole) => {
    setRoleLoading(true)
    try {
      const updated = await profileApi.updateRole(role)
      updateUser({ role: updated.role as UserRole })
    } catch { /* ignore — navigate anyway */ }
    finally {
      setRoleLoading(false)
      navigate('/dashboard')
    }
  }

  const handleGithub = () => {
    if (!GITHUB_CLIENT_ID) {
      setFormError('GitHub OAuth is not configured. Add VITE_GITHUB_CLIENT_ID to .env.local.')
      return
    }
    const url = `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&scope=user:email`
    window.location.href = url
  }

  const handleForgotSubmit = async (totpCode?: string) => {
    if (!forgotEmail) return
    setForgotStatus('sending')
    setForgotTotpError(null)
    try {
      const res = await authApi.forgotPassword(forgotEmail, totpCode)
      if (res.requires_totp) {
        // Account has 2FA — show the authenticator prompt
        setForgotNeedsTotp(true)
        setForgotStatus('idle')
        if (res.totp_invalid) setForgotTotpError('Invalid authenticator code. Please try again.')
      } else {
        setForgotStatus('sent')
      }
    } catch {
      setForgotStatus('error')
    }
  }

  return (
    <div className="relative flex min-h-screen w-full bg-background">
      {showRoleModal && (
        <RoleModal onSelect={handleRoleSelect} loading={roleLoading} />
      )}
      <div className="absolute top-4 right-4 z-50"><ModeToggle /></div>
      <BrandPanel />

      <div className="flex flex-1 flex-col items-center justify-center px-6 py-14">
        <div className="mb-8 flex items-center gap-2.5 lg:hidden">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-foreground text-background">
            <QuantumLogo size={18} />
          </div>
          <span className="text-sm font-semibold text-foreground">QuantumShield</span>
        </div>

        <div className="w-full max-w-[340px]">
          {sessionExpired && (
            <div className="mb-5 flex items-start gap-2.5 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3.5 py-3 text-xs text-amber-600 dark:text-amber-400">
              <Info size={13} className="mt-0.5 shrink-0" />
              <span>Your session expired. Please sign in again.</span>
            </div>
          )}
          <div className="mb-6">
            <h1 className="text-[1.35rem] font-semibold tracking-tight text-foreground">Welcome back</h1>
            <p className="mt-1 text-sm text-muted-foreground">Sign in to your account to continue</p>
          </div>

          {/* Demo credentials */}
          <div className="mb-5">
            <p className="mb-2 font-mono text-[9px] uppercase tracking-widest text-muted-foreground/50">Demo Credentials</p>
            <div className="grid grid-cols-3 gap-1.5">
              {DEMO_USERS.map(d => (
                <button key={d.role} type="button" onClick={() => fillDemo(d.email, d.password)}
                  className="rounded-md border border-border/60 px-2 py-2 text-left transition-colors hover:border-foreground/40 hover:bg-muted/30">
                  <p className="font-mono text-[9px] font-semibold uppercase tracking-widest text-muted-foreground">{d.role}</p>
                  <p className="mt-0.5 truncate text-[10px] text-foreground/70">{d.email}</p>
                  <p className="font-mono text-[10px] text-muted-foreground/50">{d.password}</p>
                </button>
              ))}
            </div>
          </div>

          {/* OAuth buttons */}
          <div className="flex flex-col gap-2.5">
            <GoogleButton
              onSuccess={handleGoogleSuccess}
              onError={() => setFormError('Google sign-in failed.')}
              text="signin_with"
            />
            <Button variant="outline" type="button" className="h-9 w-full gap-2.5 font-normal"
              onClick={handleGithub}>
              <GithubIcon /> Continue with GitHub
            </Button>
          </div>

          <div className="my-5 flex items-center gap-3">
            <Separator className="flex-1" />
            <span className="text-[11px] text-muted-foreground/50">or sign in with email</span>
            <Separator className="flex-1" />
          </div>

          {/* 2FA step */}
          {twoFaStep ? (
            <form onSubmit={handleSubmit} noValidate className="flex flex-col gap-3.5">
              <div className="rounded-lg border border-border/60 bg-muted/20 p-3 text-xs text-muted-foreground">
                Two-factor authentication is enabled on this account. Enter the 6-digit code from your authenticator app.
              </div>
              <div>
                <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                  Authenticator code
                </label>
                <Input
                  type="text"
                  inputMode="numeric"
                  maxLength={6}
                  placeholder="000000"
                  value={totpCode}
                  onChange={e => { setTotpCode(e.target.value.replace(/\D/g, '')); setTotpError(null) }}
                  autoFocus
                  className="font-mono text-center tracking-[0.4em]"
                />
                {totpError && <p className="mt-1 text-[11px] text-destructive">{totpError}</p>}
              </div>
              <Button type="submit" className="h-9 w-full gap-2" disabled={loading} aria-busy={loading}>
                {loading
                  ? <><span aria-hidden="true" className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent inline-block" /> Verifying…</>
                  : <>Verify & Sign In <ArrowRight size={13} /></>}
              </Button>
              <button type="button" className="text-center text-xs text-muted-foreground hover:underline"
                onClick={() => { setTwoFaStep(false); setTotpCode('') }}>
                ← Back
              </button>
            </form>
          ) : (
            <form onSubmit={handleSubmit} noValidate className="flex flex-col gap-3.5">
              <div>
                <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                  Email address
                </label>
                <Input
                  type="email"
                  placeholder="you@company.com"
                  value={form.email}
                  onChange={handleChange('email')}
                  onBlur={handleBlur('email')}
                  className={errors.email && touched.email ? 'border-destructive focus:ring-destructive/30' : ''}
                  autoComplete="email"
                />
                <FieldError msg={touched.email ? errors.email : undefined} />
              </div>

              <div>
                <div className="mb-1.5 flex items-center justify-between">
                  <label className="font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                    Password
                  </label>
                  <button type="button" className="text-[11px] text-primary hover:underline"
                    onClick={() => { setForgotOpen(o => !o); setForgotEmail(form.email); setForgotStatus('idle'); setForgotNeedsTotp(false); setForgotTotpCode(''); setForgotTotpError(null) }}>
                    Forgot?
                  </button>
                </div>
                <div className="relative">
                  <Input
                    type={showPassword ? 'text' : 'password'}
                    placeholder="••••••••"
                    value={form.password}
                    onChange={handleChange('password')}
                    onBlur={handleBlur('password')}
                    className={`pr-9 ${errors.password && touched.password ? 'border-destructive focus:ring-destructive/30' : ''}`}
                    autoComplete="current-password"
                  />
                  <button
                    type="button"
                    tabIndex={-1}
                    onClick={() => setShowPassword(v => !v)}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                  >
                    {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                </div>
                <FieldError msg={touched.password ? errors.password : undefined} />

                {/* Forgot password panel */}
                {forgotOpen && (
                  <div className="mt-2 rounded-lg border border-border/60 bg-muted/20 p-3">
                    {forgotStatus === 'sent' ? (
                      <p className="text-[11px] text-green-500">
                        If that address is registered, a reset link was sent. Check your spam folder if you don't see it within a few minutes.
                      </p>
                    ) : forgotNeedsTotp ? (
                      /* ── 2FA step: account requires authenticator code ── */
                      <div className="flex flex-col gap-2">
                        <p className="text-[11px] text-muted-foreground">
                          This account has two-factor authentication enabled. Enter your authenticator code to receive the reset link.
                        </p>
                        <Input
                          type="text"
                          inputMode="numeric"
                          maxLength={6}
                          placeholder="000000"
                          value={forgotTotpCode}
                          onChange={e => { setForgotTotpCode(e.target.value.replace(/\D/g, '')); setForgotTotpError(null) }}
                          onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); void handleForgotSubmit(forgotTotpCode) } }}
                          className="h-8 font-mono text-center tracking-[0.4em] text-xs"
                          autoFocus
                        />
                        {forgotTotpError && <p className="text-[11px] text-destructive">{forgotTotpError}</p>}
                        {forgotStatus === 'error' && <p className="text-[11px] text-destructive">Something went wrong. Try again.</p>}
                        <Button
                          type="button"
                          size="sm"
                          className="h-7 text-xs"
                          disabled={forgotStatus === 'sending' || forgotTotpCode.length !== 6}
                          onClick={() => void handleForgotSubmit(forgotTotpCode)}
                        >
                          {forgotStatus === 'sending' ? 'Verifying…' : 'Verify & send link'}
                        </Button>
                        <button type="button" className="text-center text-[11px] text-muted-foreground hover:underline"
                          onClick={() => { setForgotNeedsTotp(false); setForgotTotpCode(''); setForgotTotpError(null) }}>
                          ← Back
                        </button>
                      </div>
                    ) : (
                      /* ── Step 1: email input ── */
                      <div className="flex flex-col gap-2">
                        <p className="text-[11px] text-muted-foreground">Enter your email to receive a reset link.</p>
                        <Input
                          type="email"
                          placeholder="you@company.com"
                          value={forgotEmail}
                          onChange={e => setForgotEmail(e.target.value)}
                          onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); void handleForgotSubmit() } }}
                          className="h-8 text-xs"
                        />
                        {forgotStatus === 'error' && (
                          <p className="text-[11px] text-destructive">Something went wrong. Try again.</p>
                        )}
                        <Button
                          type="button"
                          size="sm"
                          className="h-7 text-xs"
                          disabled={forgotStatus === 'sending'}
                          onClick={() => void handleForgotSubmit()}
                        >
                          {forgotStatus === 'sending' ? 'Sending…' : 'Send reset link'}
                        </Button>
                      </div>
                    )}
                  </div>
                )}
              </div>

              <label className="flex cursor-pointer items-center gap-2 text-xs text-muted-foreground select-none">
                <input type="checkbox" checked={remember} onChange={e => setRemember(e.target.checked)}
                  className="h-3.5 w-3.5 rounded accent-primary" />
                Keep me signed in for the day 
              </label>

              {formError && <p className="text-[11px] text-destructive">{formError}</p>}

              <Button type="submit" className="mt-1 h-9 w-full gap-2" disabled={loading} aria-busy={loading}>
                {loading
                  ? <><span aria-hidden="true" className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent inline-block" /> Signing in…</>
                  : <>Sign In <ArrowRight size={13} /></>}
              </Button>
            </form>
          )}

          <p className="mt-5 text-center text-xs text-muted-foreground">
            Don&apos;t have an account?{' '}
            <button type="button" onClick={() => navigate('/signup')} className="font-medium text-primary hover:underline">
              Create one →
            </button>
          </p>

          <div className="mt-5 flex items-center justify-center gap-3">
            {([
              { icon: <Lock size={10} />, text: 'TLS 1.3' },
              { icon: <KeyRound size={10} />, text: 'JWT Auth' },
              { icon: <ShieldCheck size={10} />, text: 'bcrypt' },
            ] as { icon: React.ReactNode; text: string }[]).map(b => (
              <div key={b.text} className="flex items-center gap-1 text-[10px] text-muted-foreground/40">
                <span className="text-muted-foreground/30">{b.icon}</span>
                <span className="font-mono">{b.text}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
