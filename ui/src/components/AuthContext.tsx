// 3.4: who is logged in, and what they may do. Display only: the server enforces every permission.

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { setCsrfToken, setUnauthorizedHandler } from '../api/client'
import { logout as apiLogout, type Capability, type Me } from '../api/auth'

interface AuthValue {
  me: Me | null
  can: (cap: Capability) => boolean
  logout: () => Promise<void>
}

const AuthCtx = createContext<AuthValue | null>(null)

export function AuthProvider({ initial, onSignedOut, children }: { initial: Me; onSignedOut: () => void; children: ReactNode }) {
  const [me] = useState<Me>(initial)

  useEffect(() => {
    setCsrfToken(initial.csrf_token)
    setUnauthorizedHandler(() => {
      setCsrfToken(null)
      onSignedOut()
    })
    return () => setUnauthorizedHandler(null)
  }, [initial, onSignedOut])

  const logout = useCallback(async () => {
    try {
      await apiLogout()
    } finally {
      setCsrfToken(null)
      onSignedOut()
    }
  }, [onSignedOut])

  const value = useMemo<AuthValue>(
    () => ({ me, logout, can: (cap: Capability) => me.capabilities.includes(cap) }),
    [me, logout],
  )
  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>
}

/** Outside a provider (tests, isolated renders) everything is allowed for display; the server still decides. */
const OPEN: AuthValue = { me: null, can: () => true, logout: async () => {} }

export function useAuth(): AuthValue {
  return useContext(AuthCtx) ?? OPEN
}

/** Tooltip for a control the current role cannot use. */
export function needs(cap: Capability): string {
  const who: Record<Capability, string> = {
    self: 'a logged-in user',
    read: 'the Viewer role or higher',
    review: 'the Approver, Builder, or Admin role',
    approve: 'the Approver or Admin role',
    build: 'the Builder or Admin role',
    admin: 'the Admin role',
  }
  return `Requires ${who[cap]}`
}
