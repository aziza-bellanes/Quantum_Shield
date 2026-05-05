import React from 'react'
import { Outlet } from 'react-router-dom'
import { SidebarProvider, SidebarInset } from '../ui/sidebar'
import { AppSidebar } from './AppSidebar'
import { Topbar } from './Topbar'

export const AppLayout: React.FC = () => (
  <SidebarProvider defaultOpen={true}>
    <AppSidebar />
    <SidebarInset>
      <Topbar />
      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </SidebarInset>
  </SidebarProvider>
)
