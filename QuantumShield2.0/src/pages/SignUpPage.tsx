import React, { useState } from 'react'
import { z } from 'zod'
import { ArrowRight, ShieldCheck, X, User, Briefcase } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { GoogleLogin } from '@react-oauth/google'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Separator } from '../components/ui/separator'
import { QuantumLogo } from '../components/ui/quantum-logo'
import { ModeToggle } from '../components/mode-toggle'
import { useAuth } from '../context/AuthContext'
import { profileApi } from '../lib/api'
import type { UserRole } from '../lib/types'

const GITHUB_CLIENT_ID = (import.meta.env.VITE_GITHUB_CLIENT_ID as string | undefined) ?? ''
const GOOGLE_CLIENT_ID = (import.meta.env.VITE_GOOGLE_CLIENT_ID as string | undefined) ?? ''

const TERMS_CONTENT = `
Terms of Service — QuantumShield Platform

Last updated: April 2026

1. Acceptance of Terms
By creating an account and using QuantumShield you agree to these Terms of Service. If you do not agree, do not use the platform.

2. Account Responsibility
You are responsible for maintaining the security of your credentials. You must not share your account or allow unauthorized access.

3. Permitted Use
QuantumShield is provided for lawful security analysis of applications you own or are authorized to test. You must not use the platform to analyze applications without authorization.

4. Data Handling
Scan results and analysis data are stored securely. You retain ownership of data you submit. We process it solely to provide the service.

5. API Keys
API keys are personal and must be kept secret. Regenerate them immediately if you suspect compromise.

6. Two-Factor Authentication
You are encouraged to enable 2FA to protect your account. QuantumShield is not liable for unauthorized access resulting from failure to enable 2FA.

7. Termination
We reserve the right to suspend or terminate accounts that violate these terms.

8. Disclaimer
The platform is provided "as is". Security scores are informational and do not guarantee the absence of vulnerabilities.

9. Contact
For questions contact support@quantumshield.io
`

const PRIVACY_CONTENT = `
Privacy Policy — QuantumShield Platform

Last updated: April 2026

1. Data We Collect
• Account information: email, name, company, phone, date of birth, location, bio
• Application data: package names, domain names, TLS certificates, scan results
• Usage data: login timestamps, browser type, IP address (session records)
• 2FA secrets (stored encrypted, never exposed in API responses)

2. How We Use Your Data
• To provide and improve the security analysis service
• To send security alerts and weekly reports (if enabled in preferences)
• To authenticate your identity and protect your account
• We do not sell your data to third parties

3. Data Storage
All data is stored in a secured database. TLS results and ML predictions are retained to enable historical trend analysis.

4. OAuth Accounts
If you sign in via Google or GitHub we receive only your email and public profile name. We do not access your repositories or other private data.

5. Cookies & Local Storage
We use localStorage/sessionStorage to store your session token. No third-party tracking cookies are used.

6. Data Retention
Your data is retained while your account is active. You may request deletion by contacting support.

7. Security
We use bcrypt for passwords, TOTP for 2FA, and JWT with expiry for sessions. TLS is enforced on all connections in production.

8. Your Rights
You may view, edit, or delete your personal information via the Account page at any time.

9. Contact
privacy@quantumshield.io
`

const signUpSchema = z.object({
  name: z
    .string()
    .min(1, 'Full name is required')
    .min(2, 'Name must be at least 2 characters')
    .max(64, 'Name must be under 64 characters')
    .regex(/^[a-zA-Z\s'-]+$/, 'Name can only contain letters, spaces, hyphens and apostrophes'),
  email: z
    .string()
    .min(1, 'Work email is required')
    .email('Please enter a valid email address'),
  password: z
    .string()
    .min(1, 'Password is required')
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password must be under 128 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number'),
  role: z.enum(['end_user', 'app_owner']),
  agreed: z.literal(true, { error: () => 'You must accept the terms to continue' }),
})

type SignUpForm = z.infer<typeof signUpSchema>
type SignUpInput = { name: string; email: string; password: string; role: UserRole; agreed: boolean }
type FormErrors = Partial<Record<keyof SignUpForm, string>>

function getStrength(pw: string) {
  let s = 0
  if (pw.length >= 8) s++
  if (/[A-Z]/.test(pw)) s++
  if (/[0-9]/.test(pw)) s++
  if (/[^A-Za-z0-9]/.test(pw)) s++
  if (pw.length >= 14) s++
  const map = [
    { label: '', barColor: 'bg-muted' },
    { label: 'Weak', barColor: 'bg-destructive' },
    { label: 'Fair', barColor: 'bg-amber-500' },
    { label: 'Good', barColor: 'bg-yellow-500' },
    { label: 'Strong', barColor: 'bg-emerald-500' },
    { label: 'Excellent', barColor: 'bg-emerald-400' },
  ]
  const textColors = ['', 'text-destructive', 'text-amber-500', 'text-yellow-500', 'text-emerald-500', 'text-emerald-400']
  return { score: s, ...map[s], textColor: textColors[s] }
}

const GithubIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
  </svg>
)

const GoogleIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24">
    <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4" />
    <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
    <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05" />
    <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335" />
  </svg>
)

const steps = [
  { n: '01', title: 'Create your account', sub: 'Takes less than 30 seconds' },
  { n: '02', title: 'Connect your apps', sub: 'SDK or API — your choice' },
  { n: '03', title: 'Get instant insights', sub: 'Live scores and risk reports' },
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
          Start protecting<br />your apps{' '}
          <span style={{ background: 'linear-gradient(135deg,#60a5fa,#34d399)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            today.
          </span>
        </h2>
        <p className="mt-4 text-sm leading-relaxed" style={{ color: 'rgba(255,255,255,0.45)' }}>
          Join security teams monitoring 927+ applications for quantum-safe compliance.
        </p>
        <div className="mt-8 flex flex-col gap-0">
          {steps.map((step, i) => (
            <div key={step.n} className="flex gap-3.5">
              <div className="flex flex-col items-center">
                <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full font-mono text-[10px] font-bold"
                  style={{ background: 'rgba(255,255,255,0.08)', color: 'rgba(255,255,255,0.6)' }}>
                  {step.n}
                </div>
                {i < steps.length - 1 && <div className="my-1 h-6 w-px" style={{ background: 'rgba(255,255,255,0.08)' }} />}
              </div>
              <div className="pb-4 pt-1">
                <p className="text-sm font-medium text-white/80">{step.title}</p>
                <p className="text-[11px]" style={{ color: 'rgba(255,255,255,0.35)' }}>{step.sub}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
      <div className="flex items-center gap-2">
        <div className="flex -space-x-2">
          {['#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b'].map(c => (
            <div key={c} className="h-7 w-7 rounded-full ring-2 ring-[hsl(222,22%,7%)]" style={{ background: c }} />
          ))}
        </div>
        <p className="text-[11px]" style={{ color: 'rgba(255,255,255,0.3)' }}>Join 2+ security engineers</p>
      </div>
    </div>
  </div>
)

const FieldError: React.FC<{ msg?: string }> = ({ msg }) =>
  msg ? <p className="mt-1 text-[11px] text-destructive">{msg}</p> : null

const PolicyModal: React.FC<{ title: string; content: string; onClose: () => void }> = ({ title, content, onClose }) => (
  <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
    <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
    <div className="relative flex max-h-[80vh] w-full max-w-lg flex-col rounded-xl border border-border bg-background shadow-2xl">
      <div className="flex items-center justify-between border-b border-border px-5 py-3.5">
        <h2 className="text-sm font-semibold text-foreground">{title}</h2>
        <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors">
          <X size={16} />
        </button>
      </div>
      <div className="overflow-y-auto p-5">
        <pre className="whitespace-pre-wrap font-sans text-xs leading-relaxed text-muted-foreground">{content.trim()}</pre>
      </div>
    </div>
  </div>
)

// ── Role selection modal (shown after first-time OAuth sign-up) ───────────────
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
}> = ({ onSuccess, onError }) => (
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
      Continue with Google
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
          text="signup_with"
        />
      </div>
    )}
  </div>
)

export const SignUpPage: React.FC = () => {
  const navigate = useNavigate()
  const { register, loginWithGoogle, updateUser } = useAuth()
  const [form, setForm] = useState<SignUpInput>({ name: '', email: '', password: '', role: 'end_user', agreed: false })
  const [errors, setErrors] = useState<FormErrors>({})
  const [touched, setTouched] = useState<Partial<Record<keyof SignUpForm, boolean>>>({})
  const [loading, setLoading] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [termsOpen, setTermsOpen] = useState(false)
  const [privacyOpen, setPrivacyOpen] = useState(false)
  const [showRoleModal, setShowRoleModal] = useState(false)
  const [roleLoading, setRoleLoading] = useState(false)

  const strength = getStrength(form.password)

  const validate = (data: SignUpInput): FormErrors => {
    const result = signUpSchema.safeParse(data)
    if (result.success) return {}
    return result.error.issues.reduce<FormErrors>((acc, issue) => {
      const key = issue.path[0] as keyof SignUpForm
      if (!acc[key]) acc[key] = issue.message
      return acc
    }, {})
  }

  const handleChange = (field: keyof SignUpInput) => (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = field === 'agreed' ? e.target.checked : e.target.value
    const next = { ...form, [field]: val }
    setForm(next)
    if (touched[field as keyof SignUpForm]) setErrors(validate(next))
  }

  const handleBlur = (field: keyof SignUpForm) => () => {
    setTouched(t => ({ ...t, [field]: true }))
    setErrors(validate(form))
  }

  const handleGoogleSuccess = async (credentialResponse: { credential?: string }) => {
    const idToken = credentialResponse.credential ?? ''
    if (!idToken) { setFormError('Google sign-up failed: no credential returned.'); return }
    const res = await loginWithGoogle(idToken)
    if (res === 'ok') navigate('/dashboard')
    else if (res === 'ok_new') setShowRoleModal(true)
    else setFormError('Google sign-up failed. Please try again.')
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
    if (!GITHUB_CLIENT_ID) { setFormError('GitHub OAuth is not configured. Add VITE_GITHUB_CLIENT_ID to .env.local.'); return }
    window.location.href = `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&scope=user:email`
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    const allTouched: Record<keyof SignUpForm, boolean> = { name: true, email: true, password: true, role: true, agreed: true }
    setTouched(allTouched)
    const errs = validate(form)
    setErrors(errs)
    if (Object.keys(errs).length > 0) return
    setLoading(true)
    setFormError(null)
    const result = await register(form.name, form.email, form.password, form.role as UserRole)
    setLoading(false)
    if (result === 'ok') navigate('/dashboard')
    else if (result === 'email_taken') setFormError('An account with this email already exists.')
    else setFormError('Registration failed. Please check your details and try again.')
  }

  return (
    <div className="relative flex min-h-screen w-full bg-background">
      {showRoleModal && (
        <RoleModal onSelect={handleRoleSelect} loading={roleLoading} />
      )}
      {termsOpen && <PolicyModal title="Terms of Service" content={TERMS_CONTENT} onClose={() => setTermsOpen(false)} />}
      {privacyOpen && <PolicyModal title="Privacy Policy" content={PRIVACY_CONTENT} onClose={() => setPrivacyOpen(false)} />}

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
          <div className="mb-6">
            <h1 className="text-[1.35rem] font-semibold tracking-tight text-foreground">Create an account</h1>
            <p className="mt-1 text-sm text-muted-foreground">Start your free trial — no credit card required</p>
          </div>

          <div className="flex flex-col gap-2.5">
            <GoogleButton
              onSuccess={handleGoogleSuccess}
              onError={() => setFormError('Google sign-up failed.')}
            />
            <Button variant="outline" type="button" className="h-9 w-full gap-2.5 font-normal" onClick={handleGithub}>
              <GithubIcon /> Continue with GitHub
            </Button>
          </div>

          <div className="my-5 flex items-center gap-3">
            <Separator className="flex-1" />
            <span className="text-[11px] text-muted-foreground/50">or register with email</span>
            <Separator className="flex-1" />
          </div>

          <form onSubmit={handleSubmit} noValidate className="flex flex-col gap-3.5">
            <div>
              <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Full name</label>
              <Input type="text" placeholder="Lay Mertilly" value={form.name}
                onChange={handleChange('name')} onBlur={handleBlur('name')}
                className={errors.name && touched.name ? 'border-destructive' : ''}
                autoComplete="name" />
              <FieldError msg={touched.name ? errors.name : undefined} />
            </div>

            <div>
              <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Work email</label>
              <Input type="email" placeholder="you@company.com" value={form.email}
                onChange={handleChange('email')} onBlur={handleBlur('email')}
                className={errors.email && touched.email ? 'border-destructive' : ''}
                autoComplete="email" />
              <FieldError msg={touched.email ? errors.email : undefined} />
            </div>

            <div>
              <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Password</label>
              <Input type="password" placeholder="Min. 8 chars, 1 uppercase, 1 number" value={form.password}
                onChange={handleChange('password')} onBlur={handleBlur('password')}
                className={errors.password && touched.password ? 'border-destructive' : ''}
                autoComplete="new-password" />
              {form.password.length > 0 && (
                <div className="mt-1.5 flex flex-col gap-1">
                  <div className="flex gap-1">
                    {[1, 2, 3, 4].map(i => (
                      <div key={i} className="h-1 flex-1 overflow-hidden rounded-full bg-muted">
                        <div className={`h-full rounded-full transition-all duration-300 ${i <= strength.score ? strength.barColor : ''}`}
                          style={{ width: i <= strength.score ? '100%' : '0%' }} />
                      </div>
                    ))}
                  </div>
                  {strength.label && <p className={`font-mono text-[10px] ${strength.textColor}`}>{strength.label}</p>}
                </div>
              )}
              <FieldError msg={touched.password ? errors.password : undefined} />
            </div>

            <div>
              <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Account type</label>
              <select value={form.role}
                onChange={e => { setForm(f => ({ ...f, role: e.target.value as UserRole })) }}
                className="h-9 w-full rounded-lg border border-input bg-background px-3 font-mono text-xs text-foreground outline-none focus:border-ring">
                <option value="end_user">End User — browse and monitor applications</option>
                <option value="app_owner">App Owner — submit and analyze your own apps</option>
              </select>
            </div>

            <div>
              <label className="flex cursor-pointer items-start gap-2 text-xs text-muted-foreground select-none">
                <input type="checkbox" checked={form.agreed}
                  onChange={handleChange('agreed')} onBlur={handleBlur('agreed')}
                  className="mt-0.5 h-3.5 w-3.5 shrink-0 rounded accent-primary" />
                <span>I agree to the{' '}
                  <button type="button" onClick={() => setTermsOpen(true)} className="text-primary hover:underline">Terms of Service</button>
                  {' '}and{' '}
                  <button type="button" onClick={() => setPrivacyOpen(true)} className="text-primary hover:underline">Privacy Policy</button>
                </span>
              </label>
              <FieldError msg={touched.agreed ? errors.agreed : undefined} />
            </div>

            {formError && <p className="text-[11px] text-destructive">{formError}</p>}

            <Button type="submit" className="mt-1 h-9 w-full gap-2" disabled={loading} aria-busy={loading}>
              {loading
                ? <><span aria-hidden="true" className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent inline-block" /> Creating account…</>
                : <>Create Account <ArrowRight size={13} /></>}
            </Button>
          </form>

          <p className="mt-5 text-center text-xs text-muted-foreground">
            Already have an account?{' '}
            <button type="button" onClick={() => navigate('/login')} className="font-medium text-primary hover:underline">
              Sign in →
            </button>
          </p>

          <div className="mt-5 flex items-center justify-center gap-3">
            {[{ icon: <ShieldCheck size={10} />, text: 'NIST FIPS 203' }, { icon: <ShieldCheck size={10} />, text: 'GDPR Compliant' }, { icon: <ShieldCheck size={10} />, text: 'TLS 1.3 Secured' }].map(b => (
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
