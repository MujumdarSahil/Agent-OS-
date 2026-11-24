// src/api/auth.ts — 3.4 access: setup, login, me, own password and API tokens, users (admin), legacy token (admin).
// The server enforces every permission; the UI only hides or disables what the caller cannot do.

import { api } from './client'

export type Role = 'viewer' | 'approver' | 'builder' | 'admin'
export type Capability = 'self' | 'read' | 'review' | 'approve' | 'build' | 'admin'
export const ROLES: Role[] = ['viewer', 'approver', 'builder', 'admin']

export interface AuthStatus {
  setup_required: boolean
  version: string
  roles: Record<Role, string>
}

export interface Me {
  kind: 'session' | 'pat' | 'legacy'
  role: Role
  user_id: string | null
  username: string | null
  display_name: string | null
  token_name: string | null
  capabilities: Capability[]
  csrf_token: string | null
  separation_of_duties: boolean
}

export interface User {
  id: string
  username: string
  display_name: string
  role: Role
  disabled: boolean
  created_at: string | null
  updated_at: string | null
  password_changed_at: string | null
}

export interface ApiToken {
  token_id: string
  user_id: string
  name: string
  prefix: string
  created_at: string
  expires_at: string
  last_used_at: string | null
  revoked_at: string | null
  active: boolean
}

export interface LegacyTokenStatus {
  enabled: boolean
  source: 'env' | 'file'
  path: string | null
  can_rotate: boolean
}

export const getAuthStatus = () => api.get<AuthStatus>('/v2/auth/status').then(r => r.data)
export const getMe = () => api.get<Me>('/v2/auth/me').then(r => r.data)
export const login = (username: string, password: string) =>
  api.post<{ user: User; me: Me }>('/v2/auth/login', { username, password }).then(r => r.data)
/** First admin: only while no user exists, and only with the local API token (sent once, never stored). */
export const setup = (localToken: string, username: string, displayName: string, password: string) =>
  api
    .post<{ user: User; me: Me }>(
      '/v2/auth/setup',
      { username, display_name: displayName || null, password },
      { headers: { Authorization: `Bearer ${localToken}` } },
    )
    .then(r => r.data)
export const logout = () => api.post('/v2/auth/logout').then(r => r.data)
export const changePassword = (currentPassword: string, newPassword: string) =>
  api.post('/v2/auth/password', { current_password: currentPassword, new_password: newPassword }).then(r => r.data)

export const listMyTokens = () => api.get<ApiToken[]>('/v2/auth/tokens').then(r => r.data)
export const createMyToken = (name: string, expiresInDays: number) =>
  api.post<ApiToken & { token: string }>('/v2/auth/tokens', { name, expires_in_days: expiresInDays }).then(r => r.data)
export const revokeMyToken = (tokenId: string) => api.delete<ApiToken>(`/v2/auth/tokens/${tokenId}`).then(r => r.data)

export const listUsers = () => api.get<User[]>('/v2/users').then(r => r.data)
export const createUser = (u: { username: string; display_name?: string; role: Role; password: string }) =>
  api.post<User>('/v2/users', u).then(r => r.data)
export const updateUser = (id: string, patch: { display_name?: string; role?: Role; disabled?: boolean }) =>
  api.put<User>(`/v2/users/${id}`, patch).then(r => r.data)
export const resetPassword = (id: string, newPassword: string) =>
  api.post(`/v2/users/${id}/password`, { new_password: newPassword }).then(r => r.data)

export const getLegacyToken = () => api.get<LegacyTokenStatus>('/v2/access/legacy-token').then(r => r.data)
export const setLegacyTokenEnabled = (enabled: boolean) =>
  api.put<LegacyTokenStatus>('/v2/access/legacy-token', { enabled }).then(r => r.data)
export const rotateLegacyToken = () =>
  api.post<{ token: string; path: string; note: string }>('/v2/access/legacy-token/rotate').then(r => r.data)

export const ROLE_LABEL: Record<Role, string> = {
  viewer: 'Viewer',
  approver: 'Approver',
  builder: 'Builder',
  admin: 'Admin',
}
