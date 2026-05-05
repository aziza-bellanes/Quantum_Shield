import React, { useState, useEffect } from 'react'
import { useNavigate, useSearchParams, Link } from 'react-router-dom'
import { Eye, EyeOff, Lock, CheckCircle2, AlertCircle } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { profileApi } from '../lib/api'
import { cn } from '../lib/utils'

function passwordStrength(pw: string): { label: string; color: string; width: string } {
  if (!pw) return { label: '', color: '', width: 'w-0' }
  let score = 0
  if (pw.length >= 8) score++
  if (/[A-Z]/.test(pw)) score++
  if (/[0-9]/.test(pw)) score++
  if (/[^A-Za-z0-9]/.test(pw)) score++
  const map: Record<number, { label: string; color: string; width: string }> = {
    1: { label: 'Weak', color: 'bg-red-500', width: 'w-1/4' },
    2: { label: 'Fair', color: 'bg-orange-400', width: 'w-2/4' },
    3: { label: 'Good', color: 'bg-yellow-400', width: 'w-3/4' },
    4: { label: 'Strong', color: 'bg-emerald-500', width: 'w-full' },
  }
  return map[score] ?? { label: '', color: '', width: 'w-0' }
}

export const ResetPasswordPage: React.FC = () => {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const token = searchParams.get('token') ?? ''

  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle')
  const [errorMsg, setErrorMsg] = useState('')

  const strength = passwordStrength(password)
  const mismatch = confirm.length > 0 && password !== confirm

  useEffect(() => {
    if (!token) {
      Promise.resolve().then(() => {
        setStatus('error')
        setErrorMsg('No reset token found. Please request a new password-reset link.')
      })
    }
  }, [token])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (password !== confirm) return
    if (!token) return
    setStatus('loading')
    setErrorMsg('')
    try {
      await profileApi.resetPassword(token, password)
      setStatus('success')
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to reset password.'
      setStatus('error')
      setErrorMsg(msg)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <div className="w-full max-w-sm space-y-6">
        {/* Logo / Brand */}
        <div className="flex flex-col items-center gap-2">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10">
            <Lock size={20} className="text-primary" />
          </div>
          <h1 className="text-lg font-bold text-foreground">Reset Password</h1>
          <p className="text-center text-xs text-muted-foreground">
            Enter a new password for your QuantumShield account.
          </p>
        </div>

        {/* Success state */}
        {status === 'success' && (
          <div className="flex flex-col items-center gap-3 rounded-xl border border-emerald-200 bg-emerald-500/5 p-6 text-center">
            <CheckCircle2 size={32} className="text-emerald-500" />
            <p className="text-sm font-medium text-foreground">Password updated!</p>
            <p className="text-xs text-muted-foreground">You can now sign in with your new password.</p>
            <Button size="sm" className="mt-2" onClick={() => navigate('/login')}>
              Go to Sign In
            </Button>
          </div>
        )}

        {/* Error state (token missing/invalid, no form) */}
        {status === 'error' && !token && (
          <div className="flex flex-col items-center gap-3 rounded-xl border border-red-200 bg-red-500/5 p-6 text-center">
            <AlertCircle size={28} className="text-destructive" />
            <p className="text-sm text-destructive">{errorMsg}</p>
            <Link to="/login" className="text-xs text-primary underline">Back to Sign In</Link>
          </div>
        )}

        {/* Reset form */}
        {status !== 'success' && token && (
          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            {/* Error banner (after submission) */}
            {status === 'error' && errorMsg && (
              <div className="flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/5 px-3 py-2">
                <AlertCircle size={14} className="shrink-0 text-destructive" />
                <p className="text-xs text-destructive">{errorMsg}</p>
              </div>
            )}

            {/* New password */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-foreground">New Password</label>
              <div className="relative">
                <Input
                  type={showPw ? 'text' : 'password'}
                  placeholder="Min 8 characters"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required
                  minLength={8}
                  className="pr-9 text-sm"
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  onClick={() => setShowPw(v => !v)}
                  tabIndex={-1}
                >
                  {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
              {/* Strength bar */}
              {password && (
                <div className="space-y-1">
                  <div className="h-1 w-full rounded-full bg-muted overflow-hidden">
                    <div className={cn('h-1 rounded-full transition-all', strength.color, strength.width)} />
                  </div>
                  <p className="text-[10px] text-muted-foreground">{strength.label}</p>
                </div>
              )}
            </div>

            {/* Confirm password */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-foreground">Confirm Password</label>
              <div className="relative">
                <Input
                  type={showConfirm ? 'text' : 'password'}
                  placeholder="Repeat new password"
                  value={confirm}
                  onChange={e => setConfirm(e.target.value)}
                  required
                  className={cn('pr-9 text-sm', mismatch && 'border-destructive focus-visible:ring-destructive')}
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  onClick={() => setShowConfirm(v => !v)}
                  tabIndex={-1}
                >
                  {showConfirm ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
              {mismatch && (
                <p className="text-[10px] text-destructive">Passwords do not match</p>
              )}
            </div>

            <Button
              type="submit"
              className="w-full"
              disabled={status === 'loading' || !password || !confirm || mismatch}
            >
              {status === 'loading' ? (
                <span className="flex items-center gap-2">
                  <span aria-hidden="true" className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" />
                  Updating…
                </span>
              ) : 'Set New Password'}
            </Button>

            <p className="text-center text-xs text-muted-foreground">
              Remember it?{' '}
              <Link to="/login" className="font-medium text-primary hover:underline">Sign in</Link>
            </p>
          </form>
        )}
      </div>
    </div>
  )
}
