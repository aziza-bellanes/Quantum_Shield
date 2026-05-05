import React, { createContext, useContext, useState, useEffect } from 'react'
import type { User, UserRole } from '../lib/types'
import { authApi, saveToken, clearToken, getToken } from '../lib/api'

type LoginResult = 'ok' | 'requires_2fa' | 'invalid_credentials' | 'error'
type OAuthResult = 'ok' | 'ok_new' | 'error'

interface AuthContextValue {
  user: User | null
  loading: boolean
  login: (email: string, password: string, remember?: boolean, totpCode?: string) => Promise<LoginResult>
  loginWithGoogle: (credential: string) => Promise<OAuthResult>
  loginWithGithub: (code: string) => Promise<OAuthResult>
  register: (name: string, email: string, password: string, role: UserRole) => Promise<'ok' | 'email_taken' | 'error'>
  logout: () => void
  updateUser: (updates: Partial<User>) => void
}

const LS_KEY = 'qs_user'
const SESSION_EXPIRED_KEY = 'qs_session_expired'

const AuthContext = createContext<AuthContextValue | null>(null)

function buildUser(raw: { id: number; email: string; name: string | null; company?: string | null; phone?: string | null; date_of_birth?: string | null; location?: string | null; bio?: string | null; totp_enabled?: boolean; role: string; created_at: string }): User {
  const name = raw.name ?? raw.email.split('@')[0]
  const words = name.trim().split(/\s+/)
  const initials = words.length >= 2
    ? (words[0][0] + words[words.length - 1][0]).toUpperCase()
    : name.slice(0, 2).toUpperCase()
  const joinDate = new Date(raw.created_at).toLocaleDateString('en-US', { month: 'short', year: 'numeric' })
  return {
    id: String(raw.id),
    name,
    email: raw.email,
    company: raw.company ?? null,
    phone: raw.phone ?? null,
    dateOfBirth: raw.date_of_birth ?? null,
    location: raw.location ?? null,
    bio: raw.bio ?? null,
    totpEnabled: raw.totp_enabled ?? false,
    role: raw.role as UserRole,
    initials,
    joinDate,
  }
}

async function hydrateAndSave(setUser: (u: User) => void) {
  const raw = await authApi.me()
  const u = buildUser(raw)
  setUser(u)
  localStorage.setItem(LS_KEY, JSON.stringify(u))
  return u
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  // On mount: if a token exists, validate it via /auth/me and restore session.
  // If no token is present we do NOT restore from the qs_user cache — that would
  // cause a visible flash of "logged-in" UI before ProtectedRoute redirects.
  useEffect(() => {
    const token = getToken()
    if (!token) {
      // Ensure stale cache is cleared so ProtectedRoute sees null immediately.
      localStorage.removeItem(LS_KEY)
      // Defer the setState call to a microtask (required by react-hooks/set-state-in-effect)
      Promise.resolve().then(() => setLoading(false))
      return
    }

    authApi.me()
      .then(raw => {
        const u = buildUser(raw)
        setUser(u)
        localStorage.setItem(LS_KEY, JSON.stringify(u))
      })
      .catch((err: unknown) => {
        // 401 means the token expired. Flag it so LoginPage can show a message.
        const status = (err as { status?: number })?.status
        if (status === 401) {
          sessionStorage.setItem(SESSION_EXPIRED_KEY, '1')
        }
        clearToken()
        localStorage.removeItem(LS_KEY)
      })
      .finally(() => setLoading(false))
  }, [])

  const login = async (
    email: string,
    password: string,
    remember = true,
    totpCode?: string,
  ): Promise<LoginResult> => {
    try {
      const res = await authApi.login(email, password, totpCode)
      if (res.requires_2fa) return 'requires_2fa'
      saveToken(res.access_token, remember)
      await hydrateAndSave(setUser)
      return 'ok'
    } catch (err: unknown) {
      if (err instanceof Error && 'status' in err) {
        const status = (err as { status: number }).status
        if (status === 401) return 'invalid_credentials'
      }
      return 'error'
    }
  }

  const loginWithGoogle = async (credential: string): Promise<OAuthResult> => {
    try {
      const res = await authApi.googleAuth(credential)
      saveToken(res.access_token)
      const raw = await authApi.me()
      const u = buildUser(raw)
      setUser(u)
      localStorage.setItem(LS_KEY, JSON.stringify(u))
      // Detect first-time sign-up: account created within the last 60 seconds
      const isNew = Date.now() - new Date(raw.created_at + (raw.created_at.endsWith('Z') ? '' : 'Z')).getTime() < 60_000
      return isNew ? 'ok_new' : 'ok'
    } catch {
      return 'error'
    }
  }

  const loginWithGithub = async (code: string): Promise<OAuthResult> => {
    try {
      const res = await authApi.githubAuth(code)
      saveToken(res.access_token)
      const raw = await authApi.me()
      const u = buildUser(raw)
      setUser(u)
      localStorage.setItem(LS_KEY, JSON.stringify(u))
      // Detect first-time sign-up: account created within the last 60 seconds
      const isNew = Date.now() - new Date(raw.created_at + (raw.created_at.endsWith('Z') ? '' : 'Z')).getTime() < 60_000
      return isNew ? 'ok_new' : 'ok'
    } catch {
      return 'error'
    }
  }

  const register = async (
    name: string,
    email: string,
    password: string,
    role: UserRole,
  ): Promise<'ok' | 'email_taken' | 'error'> => {
    try {
      const { access_token } = await authApi.register(name, email, password, role)
      saveToken(access_token)
      await hydrateAndSave(setUser)
      return 'ok'
    } catch (err: unknown) {
      if (err instanceof Error && 'status' in err) {
        const status = (err as { status: number }).status
        if (status === 409) return 'email_taken'
      }
      return 'error'
    }
  }

  const logout = () => {
    clearToken()
    localStorage.removeItem(LS_KEY)
    setUser(null)
  }

  const updateUser = (updates: Partial<User>) => {
    setUser(prev => {
      if (!prev) return prev
      const next = { ...prev, ...updates }
      // Recompute initials if name changed
      if (updates.name) {
        const words = updates.name.trim().split(/\s+/)
        next.initials = words.length >= 2
          ? (words[0][0] + words[words.length - 1][0]).toUpperCase()
          : updates.name.slice(0, 2).toUpperCase()
      }
      localStorage.setItem(LS_KEY, JSON.stringify(next))
      return next
    })
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, loginWithGoogle, loginWithGithub, register, logout, updateUser }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
