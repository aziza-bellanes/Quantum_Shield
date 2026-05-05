import React, { useState } from 'react'
import { Sun, Moon, Bell, ShieldAlert, ScanSearch, TrendingUp, UserPlus, AlertTriangle, Clock, CheckCircle, XCircle, FileText, X } from 'lucide-react'
import { useLocation } from 'react-router-dom'
import { Button } from '../ui/button'
import { SidebarTrigger } from '../ui/sidebar'
import { Separator } from '../ui/separator'
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
} from '../ui/dropdown-menu'
import { useTheme } from '@/components/theme-provider'
import { useAuth } from '@/context/AuthContext'
import { useNotifications } from '@/hooks/useNotifications'
import type { NotifKind } from '@/hooks/useNotifications'

function kindIcon(kind: NotifKind) {
  switch (kind) {
    case 'new_user':          return UserPlus
    case 'scan_complete':
    case 'own_scan_complete': return CheckCircle
    case 'scan_failed':
    case 'own_scan_failed':   return XCircle
    case 'high_risk':
    case 'own_high_risk':     return ShieldAlert
    case 'cpu_alert':         return AlertTriangle
    case 'pending_backlog':   return Clock
    case 'pqc_ready':         return TrendingUp
    case 'report_ready':      return FileText
    case 'new_app_public':    return ScanSearch
    default:                  return ScanSearch
  }
}

function kindColor(kind: NotifKind): string {
  switch (kind) {
    case 'scan_failed':
    case 'own_scan_failed':
    case 'cpu_alert':         return 'text-destructive'
    case 'high_risk':
    case 'own_high_risk':     return 'text-amber-500'
    case 'scan_complete':
    case 'own_scan_complete':
    case 'pqc_ready':         return 'text-green-500'
    default:                  return 'text-primary'
  }
}

const PAGE_META: Record<string, { title: string; description: string }> = {
  '/dashboard': { title: 'Dashboard', description: 'TLS 1.3 & Quantum-Safe Security Analysis' },
  '/browse':    { title: 'Browse Applications', description: 'Search and view application security information' },
  '/reports':   { title: 'Reports', description: 'Security reports and compliance summaries' },
  '/account':   { title: 'Account', description: 'Manage your profile and preferences' },
  '/contact':   { title: 'Contact Us', description: 'Get in touch with the security team' },
  '/analyze':   { title: 'Analyze App', description: 'Submit an application for PQC security analysis' },
  '/my-apps':   { title: 'My Applications', description: 'Manage your application portfolio' },
  '/users':     { title: 'User Management', description: 'Manage platform users and roles' },
  '/system':    { title: 'System Monitor', description: 'Platform health, uptime and performance' },
  '/database':  { title: 'DB Management', description: 'Database status, sync and configuration' },
}

export const Topbar: React.FC = () => {
  const { pathname } = useLocation()
  const meta = PAGE_META[pathname] ?? { title: 'QuantumShield', description: '' }
  const { theme, setTheme } = useTheme()
  const { user } = useAuth()
  const [notifOpen, setNotifOpen] = useState(false)
  const { notifications, unreadCount, markRead, markAllRead, dismiss, dismissAll } = useNotifications(user?.role, user?.id)
  const isDark = theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches)

  return (
    <header className="sticky top-0 z-50 flex h-14 shrink-0 items-center gap-2 border-b border-border bg-background/95 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/80">
      <div className="flex items-center gap-2">
        <SidebarTrigger className="-ml-1" />
        <Separator orientation="vertical" className="mr-1 h-4" />
        <div>
          <h1 className="text-sm font-semibold tracking-tight text-foreground leading-none">
            {meta.title}
          </h1>
          <p className="mt-0.5 hidden text-[11px] leading-none text-muted-foreground sm:block">
            {meta.description}
          </p>
        </div>
      </div>

      <div className="ml-auto flex items-center gap-1">
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8 text-muted-foreground"
          aria-label="Toggle theme"
          onClick={() => setTheme(isDark ? 'light' : 'dark')}
        >
          {isDark ? <Sun size={14} /> : <Moon size={14} />}
        </Button>

        <DropdownMenu open={notifOpen} onOpenChange={setNotifOpen}>
          <DropdownMenuTrigger asChild>
            <div className="relative">
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8 text-muted-foreground"
                aria-label="Notifications"
              >
                <Bell size={14} />
              </Button>
              {unreadCount > 0 && (
                <span className="pointer-events-none absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-destructive ring-2 ring-background" />
              )}
            </div>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-80 p-0" sideOffset={8}>
            <div className="flex items-center justify-between px-4 py-3 border-b border-border">
              <span className="text-sm font-semibold text-foreground">Notifications</span>
              <div className="flex items-center gap-3">
                {unreadCount > 0 && (
                  <button
                    className="font-mono text-[10px] text-primary hover:underline"
                    onClick={markAllRead}
                  >
                    Mark all read
                  </button>
                )}
                {notifications.length > 0 && (
                  <button
                    className="font-mono text-[10px] text-muted-foreground hover:text-destructive hover:underline"
                    onClick={dismissAll}
                  >
                    Clear all
                  </button>
                )}
              </div>
            </div>
            <div className="flex flex-col max-h-80 overflow-y-auto">
              {notifications.length === 0 ? (
                <p className="px-4 py-6 text-center text-xs text-muted-foreground">No notifications</p>
              ) : notifications.map(n => {
                const Icon = kindIcon(n.kind)
                const iconColor = kindColor(n.kind)
                return (
                  <div
                    key={n.id}
                    className={`flex items-start gap-3 px-4 py-3 border-b border-border/40 last:border-0 transition-colors ${n.unread ? 'bg-muted/30' : ''}`}
                    onClick={() => markRead(n.id)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={e => e.key === 'Enter' && markRead(n.id)}
                  >
                    <div className={`mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full ${n.unread ? 'bg-primary/10' : 'bg-muted'}`}>
                      <Icon size={13} className={n.unread ? iconColor : 'text-muted-foreground'} />
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-medium text-foreground leading-snug">{n.title}</p>
                      <p className="font-mono text-[10px] text-muted-foreground mt-0.5">{n.sub}</p>
                    </div>
                    <button
                      className="mt-0.5 shrink-0 text-muted-foreground/40 hover:text-muted-foreground"
                      onClick={e => { e.stopPropagation(); dismiss(n.id) }}
                      aria-label="Dismiss"
                    >
                      <X size={12} />
                    </button>
                  </div>
                )
              })}
            </div>
          </DropdownMenuContent>
        </DropdownMenu>

        <div className="mx-1 h-5 w-px bg-border" />

        <div className="flex cursor-default items-center gap-2 rounded-md border bg-muted/30 px-2.5 py-1.5">
          <div className="flex h-5 w-5 items-center justify-center rounded-full bg-foreground font-mono text-[9px] font-bold text-background">
            {user?.initials ?? '??'}
          </div>
          <span className="hidden text-xs text-muted-foreground sm:block">{user?.email ?? ''}</span>
        </div>
      </div>
    </header>
  )
}
