import React, { useEffect, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { User, Briefcase } from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import { profileApi } from '../lib/api'
import type { UserRole } from '../lib/types'

// ── Inline role-selection modal (mirrors the one in LoginPage) ────────────────
const RoleModal: React.FC<{ onSelect: (role: UserRole) => void; loading: boolean }> = ({ onSelect, loading }) => (
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

// ── Callback page ─────────────────────────────────────────────────────────────
export const GithubCallbackPage: React.FC = () => {
  const [params] = useSearchParams()
  const { loginWithGithub, updateUser } = useAuth()
  const navigate = useNavigate()
  const called = useRef(false)
  const [showRoleModal, setShowRoleModal] = useState(false)
  const [roleLoading, setRoleLoading] = useState(false)

  useEffect(() => {
    if (called.current) return
    called.current = true
    const code = params.get('code')
    if (!code) {
      navigate('/login', { replace: true })
      return
    }
    loginWithGithub(code).then(result => {
      if (result === 'ok_new') {
        setShowRoleModal(true)   // first-time sign-in → ask for role
      } else {
        navigate(result === 'ok' ? '/dashboard' : '/login', { replace: true })
      }
    })
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const handleRoleSelect = async (role: UserRole) => {
    setRoleLoading(true)
    try {
      const updated = await profileApi.updateRole(role)
      updateUser({ role: updated.role as UserRole })
    } catch { /* ignore — navigate anyway */ }
    finally {
      setRoleLoading(false)
      navigate('/dashboard', { replace: true })
    }
  }

  if (showRoleModal) {
    return <RoleModal onSelect={handleRoleSelect} loading={roleLoading} />
  }

  return (
    <div className="flex h-screen items-center justify-center text-muted-foreground text-sm">
      <span role="status" aria-label="Signing in with GitHub"
        className="mr-3 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
      Signing in with GitHub…
    </div>
  )
}
