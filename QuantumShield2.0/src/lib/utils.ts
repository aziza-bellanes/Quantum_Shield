import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"
import type { RiskLevel, UserRole } from './types'
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}
export function scoreColor(score: number): string {
  if (score >= 90) return 'text-emerald-500 dark:text-emerald-400'
  if (score >= 75) return 'text-lime-500 dark:text-lime-400'
  if (score >= 60) return 'text-amber-500 dark:text-amber-400'
  return 'text-destructive'
}

export function scoreBarColor(score: number): string {
  if (score >= 90) return 'bg-emerald-500'
  if (score >= 75) return 'bg-lime-500'
  if (score >= 60) return 'bg-amber-500'
  return 'bg-destructive'
}

export function tlsColor(version: string): string {
  const map: Record<string, string> = {
    '1.3': 'text-emerald-500 dark:text-emerald-400',
    '1.2': 'text-yellow-500 dark:text-yellow-400',
    '1.1': 'text-amber-500 dark:text-amber-400',
    '1.0': 'text-destructive',
  }
  return map[version] ?? 'text-muted-foreground'
}

export function riskVariant(risk: RiskLevel): 'success' | 'warning' | 'destructive' {
  return risk === 'Low' ? 'success' : risk === 'Medium' ? 'warning' : 'destructive'
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}

export function formatDateTime(iso: string): string {
  const normalized = iso.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(iso) ? iso : iso + 'Z'
  return new Date(normalized).toLocaleString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

export function roleLabel(role: UserRole): string {
  const map: Record<UserRole, string> = {
    end_user: 'End User',
    app_owner: 'App Owner',
    admin: 'Administrator',
  }
  return map[role]
}
