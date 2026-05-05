import { StrictMode, Component } from 'react'
import type { ReactNode, ErrorInfo } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { GoogleOAuthProvider } from '@react-oauth/google'
import './index.css'
import { App } from './App.tsx'
import { ThemeProvider } from '@/components/theme-provider.tsx'
import { TooltipProvider } from '@/components/ui/tooltip'
import { AuthProvider } from '@/context/AuthContext.tsx'

// ── Top-level error boundary ──────────────────────────────────────────────────
// Catches any unhandled render-time error in the tree and shows a recovery UI
// instead of a blank white screen.
class ErrorBoundary extends Component<
  { children: ReactNode },
  { error: Error | null }
> {
  constructor(props: { children: ReactNode }) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error: Error) {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[ErrorBoundary]', error, info.componentStack)
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-background p-8 text-center">
          <p className="text-sm font-semibold text-foreground">Something went wrong</p>
          <p className="max-w-sm text-xs text-muted-foreground">
            {this.state.error.message || 'An unexpected error occurred.'}
          </p>
          <button
            className="mt-2 rounded-md border border-border px-4 py-2 text-xs hover:bg-muted"
            onClick={() => { this.setState({ error: null }); window.location.href = '/' }}
          >
            Reload app
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

// ── App tree ──────────────────────────────────────────────────────────────────
const GOOGLE_CLIENT_ID = (import.meta.env.VITE_GOOGLE_CLIENT_ID as string | undefined) ?? ''

const AppTree = (
  <BrowserRouter>
    <ThemeProvider defaultTheme="dark" storageKey="vite-ui-theme">
      <AuthProvider>
        <TooltipProvider>
          <App />
        </TooltipProvider>
      </AuthProvider>
    </ThemeProvider>
  </BrowserRouter>
)

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      {GOOGLE_CLIENT_ID
        ? <GoogleOAuthProvider clientId={GOOGLE_CLIENT_ID}>{AppTree}</GoogleOAuthProvider>
        : AppTree}
    </ErrorBoundary>
  </StrictMode>,
)
