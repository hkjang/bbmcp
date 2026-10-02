import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { api, ApiError, type Me, type PublicConfig } from './api'

interface AuthState {
  loading: boolean
  config: PublicConfig | null
  me: Me | null
  /** True while a hidden-iframe prompt=none attempt is in flight. */
  silentChecking: boolean
  ssoError: string | null
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  refresh: () => Promise<void>
  startSso: (returnTo?: string) => void
}

const AuthContext = createContext<AuthState | null>(null)

const SILENT_FLAG = 'bbmcp.silentSsoTried'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [loading, setLoading] = useState(true)
  const [config, setConfig] = useState<PublicConfig | null>(null)
  const [me, setMe] = useState<Me | null>(null)
  const [silentChecking, setSilentChecking] = useState(false)
  const [ssoError, setSsoError] = useState<string | null>(null)
  const frameRef = useRef<HTMLIFrameElement | null>(null)

  const loadMe = useCallback(async () => {
    try {
      setMe(await api.get<Me>('/api/me'))
      return true
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setMe(null)
        return false
      }
      throw err
    }
  }, [])

  // Silent SSO: ask Keycloak with prompt=none inside a hidden iframe. When an
  // SSO session already exists the user lands signed in without a click; when
  // it does not, Keycloak answers login_required and the login form stays.
  const attemptSilentSso = useCallback(
    (cfg: PublicConfig) =>
      new Promise<boolean>((resolve) => {
        if (!cfg.auth.keycloakEnabled || !cfg.auth.silentSso) {
          resolve(false)
          return
        }
        if (sessionStorage.getItem(SILENT_FLAG) === '1') {
          resolve(false)
          return
        }
        sessionStorage.setItem(SILENT_FLAG, '1')
        setSilentChecking(true)

        const frame = document.createElement('iframe')
        frame.style.display = 'none'
        frame.setAttribute('aria-hidden', 'true')
        frame.title = 'Keycloak 사일런트 SSO'
        frameRef.current = frame

        let settled = false
        const finish = (ok: boolean, reason?: string) => {
          if (settled) return
          settled = true
          window.removeEventListener('message', onMessage)
          clearTimeout(timer)
          frame.remove()
          frameRef.current = null
          setSilentChecking(false)
          if (!ok && reason && !/login_required|interaction_required|sso_disabled/.test(reason)) {
            setSsoError(reason)
          }
          resolve(ok)
        }

        const onMessage = (event: MessageEvent) => {
          if (event.origin !== window.location.origin) return
          const data = event.data as { type?: string; ok?: boolean; reason?: string }
          if (!data || data.type !== 'bbmcp-sso') return
          finish(Boolean(data.ok), data.reason)
        }

        const timer = window.setTimeout(() => finish(false, 'timeout'), 12000)
        window.addEventListener('message', onMessage)
        frame.src = cfg.auth.silentUrl
        document.body.appendChild(frame)
      }),
    [],
  )

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const cfg = await api.get<PublicConfig>('/api/config')
        if (cancelled) return
        setConfig(cfg)

        const params = new URLSearchParams(window.location.search)
        const err = params.get('sso_error')
        if (err) setSsoError(err)

        const signedIn = await loadMe()
        if (!signedIn && !cancelled) {
          const ok = await attemptSilentSso(cfg)
          if (ok && !cancelled) await loadMe()
        }
      } catch {
        // A failed bootstrap still renders the login screen.
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => {
      cancelled = true
      frameRef.current?.remove()
    }
  }, [attemptSilentSso, loadMe])

  const login = useCallback(
    async (username: string, password: string) => {
      await api.post('/api/auth/login', { username, password })
      sessionStorage.removeItem(SILENT_FLAG)
      await loadMe()
    },
    [loadMe],
  )

  const logout = useCallback(async () => {
    const res = await api.post<{ ok: boolean; ssoLogoutUrl?: string }>('/api/auth/logout')
    setMe(null)
    // Keep the flag set so logging out does not immediately silently sign the
    // user back in through the still-valid Keycloak session.
    sessionStorage.setItem(SILENT_FLAG, '1')
    if (res?.ssoLogoutUrl) {
      window.location.href = res.ssoLogoutUrl
      return
    }
    window.location.href = '/login'
  }, [])

  const startSso = useCallback((returnTo?: string) => {
    const target = returnTo ?? window.location.pathname + window.location.search
    sessionStorage.removeItem(SILENT_FLAG)
    window.location.href = `/auth/oidc/start?returnTo=${encodeURIComponent(target)}`
  }, [])

  const value = useMemo<AuthState>(
    () => ({
      loading,
      config,
      me,
      silentChecking,
      ssoError,
      login,
      logout,
      refresh: async () => {
        await loadMe()
      },
      startSso,
    }),
    [loading, config, me, silentChecking, ssoError, login, logout, loadMe, startSso],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}
