import React from 'react'
import {
  LayoutDashboard, AppWindow, Mail, User, LogOut,
  FileBarChart, ScanSearch, Package, Users, Activity, Database,
} from 'lucide-react'
import { useNavigate, useLocation } from 'react-router-dom'
import { cn } from '../../lib/utils'
import { roleLabel } from '../../lib/utils'
import type { UserRole } from '../../lib/types'
import { QuantumLogo } from '../ui/quantum-logo'
import { useAuth } from '../../context/AuthContext'
import {
  Sidebar, SidebarHeader, SidebarContent, SidebarFooter,
  SidebarGroup, SidebarGroupLabel, SidebarGroupContent,
  SidebarMenu, SidebarMenuItem, SidebarMenuButton,
  SidebarSeparator, useSidebar,
} from '../ui/sidebar'

interface NavItem {
  path: string
  label: string
  icon: React.ElementType
}

interface NavGroup {
  label: string
  items: NavItem[]
}

function getNavConfig(role: UserRole): NavGroup[] {
  const main: NavGroup = {
    label: 'Main',
    items: [
      { path: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
      { path: '/browse', label: 'Browse Apps', icon: AppWindow },
      { path: '/reports', label: 'Reports', icon: FileBarChart },
    ],
  }

  const tools: NavGroup = {
    label: 'Tools',
    items: [
      { path: '/analyze', label: 'Analyze App', icon: ScanSearch },
      { path: '/my-apps', label: 'My Applications', icon: Package },
    ],
  }

  const adminGroup: NavGroup = {
    label: 'Admin',
    items: [
      { path: '/users', label: 'User Management', icon: Users },
      { path: '/system', label: 'System Monitor', icon: Activity },
      { path: '/database', label: 'DB Management', icon: Database },
    ],
  }

  const general: NavGroup = {
    label: 'General',
    items: [
      { path: '/account', label: 'Account', icon: User },
      { path: '/contact', label: 'Contact Us', icon: Mail },
    ],
  }

  if (role === 'admin') return [main, tools, adminGroup, general]
  if (role === 'app_owner') return [main, tools, general]
  return [main, general]
}

export const AppSidebar: React.FC = () => {
  const { state } = useSidebar()
  const collapsed = state === 'collapsed'
  const navigate = useNavigate()
  const { pathname } = useLocation()
  const { user, logout } = useAuth()

  const navGroups = user ? getNavConfig(user.role) : []

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <Sidebar collapsible="icon">

      {/* ── Logo ── */}
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              size="lg"
              className={cn('h-auto py-2.5', collapsed && 'justify-center px-0')}
            >
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-foreground text-background">
                <QuantumLogo size={20} />
              </div>
              {!collapsed && (
                <div className="min-w-0 flex-1 overflow-hidden">
                  <p className="truncate text-sm font-semibold tracking-tight text-sidebar-foreground">
                    QuantumShield
                  </p>
                  <p className="truncate font-mono text-[9px] uppercase tracking-widest text-sidebar-foreground/40">
                    PQC Platform
                  </p>
                </div>
              )}
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>

        {!collapsed && user && (
          <div className="mx-1 rounded-md border border-sidebar-border bg-sidebar-accent/30 px-3 py-2">
            <p className="font-mono text-[9px] uppercase tracking-widest text-sidebar-foreground/40">Current Role</p>
            <p className="mt-0.5 text-xs font-medium text-sidebar-foreground">{roleLabel(user.role)}</p>
          </div>
        )}
      </SidebarHeader>

      <SidebarContent>
        {navGroups.map((group, gi) => (
          <React.Fragment key={group.label}>
            {gi > 0 && <SidebarSeparator />}
            <SidebarGroup>
              <SidebarGroupLabel>{group.label}</SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {group.items.map(({ path, label, icon: Icon }) => (
                    <SidebarMenuItem key={path}>
                      <SidebarMenuButton
                        isActive={pathname === path}
                        tooltip={label}
                        onClick={() => navigate(path)}
                        className="text-xs"
                      >
                        <Icon size={15} className="shrink-0" />
                        {!collapsed && <span className="truncate">{label}</span>}
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  ))}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          </React.Fragment>
        ))}
      </SidebarContent>

      {/* ── User footer ── */}
      <SidebarFooter>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              size="lg"
              className={cn('h-auto py-2', collapsed && 'justify-center px-0')}
              onClick={() => navigate('/account')}
            >
              <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-foreground font-mono text-[10px] font-bold text-background">
                {user?.initials ?? '??'}
              </div>
              {!collapsed && (
                <>
                  <div className="min-w-0 flex-1" title={user?.email}>
                    <p className="truncate text-[11px] font-medium text-sidebar-foreground">{user?.email ?? ''}</p>
                    <p className="truncate font-mono text-[9px] text-sidebar-foreground/40">{user ? roleLabel(user.role) : ''}</p>
                  </div>
                  <User size={13} className="text-sidebar-foreground/40" />
                </>
              )}
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>

        <button
          onClick={handleLogout}
          title="Log out"
          className={cn(
            'flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-xs',
            'text-sidebar-foreground/50 transition-colors hover:bg-destructive/10 hover:text-destructive',
            collapsed ? 'justify-center' : '',
          )}
        >
          <LogOut size={14} />
          {!collapsed && <span>Log out</span>}
        </button>
      </SidebarFooter>
    </Sidebar>
  )
}
