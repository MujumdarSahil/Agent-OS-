import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import { useState, useEffect, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  LayoutDashboard, Bot, Wrench, Users, Target, Wand2, Shield, Package, Cpu, LayoutGrid,
  Settings as SettingsIcon, Server, Key, Lock, LogOut, Workflow, Gauge, ListChecks, Hand,
  Zap, ShieldAlert, ChevronDown, ChevronRight, Bell, Mail,
} from 'lucide-react'
import { getHealth, getAuthToken, clearAuthToken } from './api/client'
import { getOverview } from './api/flows'
import AuthGate from './components/AuthGate'
import Dashboard from './pages/Dashboard'
import Agents from './pages/Agents'
import Tools from './pages/Tools'
import Squads from './pages/Squads'
import MCPServers from './pages/MCPServers'
import Providers from './pages/Providers'
import Missions from './pages/Missions'
import RunDetail from './pages/RunDetail'
import Builder from './pages/Builder'
import Governance from './pages/Governance'
import Packaging from './pages/Packaging'
import Templates from './pages/Templates'
import Settings from './pages/Settings'
import Flows from './pages/Flows'
import FlowEditor from './pages/FlowEditor'
import Overview from './pages/Overview'
import Runs from './pages/Runs'
import Approvals from './pages/Approvals'
import Triggers from './pages/Triggers'
import SecurityLog from './pages/SecurityLog'
import AuditLog from './pages/AuditLog'
import Metrics from './pages/Metrics'
import Alerts from './pages/Alerts'
import NotificationChannels from './pages/NotificationChannels'

interface NavItem { to: string; icon: ReactNode; label: string }

// 2.4e: menu by purpose. v1 pages stay reachable under "Classic (v1)", collapsed by default.
const NAV_GROUPS: { title: string; items: NavItem[] }[] = [
  { title: 'Watch', items: [
    { to: '/', icon: <Gauge size={15}/>, label: 'Overview' },
    { to: '/metrics', icon: <Gauge size={15}/>, label: 'Metrics' },
    { to: '/alerts', icon: <Bell size={15}/>, label: 'Alerts' },
  ] },
  { title: 'Work', items: [
    { to: '/runs', icon: <ListChecks size={15}/>, label: 'Runs' },
    { to: '/approvals', icon: <Hand size={15}/>, label: 'Approvals' },
  ] },
  { title: 'Build', items: [
    { to: '/flows', icon: <Workflow size={15}/>, label: 'Flows' },
    { to: '/agents', icon: <Bot size={15}/>, label: 'Agents' },
    { to: '/squads', icon: <Users size={15}/>, label: 'Squads' },
    { to: '/triggers', icon: <Zap size={15}/>, label: 'Triggers' },
  ] },
  { title: 'Connect', items: [
    { to: '/providers', icon: <Key size={15}/>, label: 'Models & keys' },
    { to: '/tools', icon: <Wrench size={15}/>, label: 'Tools' },
    { to: '/mcp-servers', icon: <Server size={15}/>, label: 'MCP servers' },
    { to: '/notifications', icon: <Mail size={15}/>, label: 'Notification channels' },
  ] },
  { title: 'Govern', items: [
    { to: '/security', icon: <ShieldAlert size={15}/>, label: 'Security log' },
    { to: '/audit', icon: <Shield size={15}/>, label: 'Audit log' },
  ] },
  { title: 'System', items: [{ to: '/settings', icon: <SettingsIcon size={15}/>, label: 'Settings' }] },
]

const CLASSIC: NavItem[] = [
  { to: '/classic/dashboard', icon: <LayoutDashboard size={15}/>, label: 'Dashboard' },
  { to: '/missions', icon: <Target size={15}/>, label: 'Missions' },
  { to: '/templates', icon: <LayoutGrid size={15}/>, label: 'Templates' },
  { to: '/builder', icon: <Wand2 size={15}/>, label: 'Builder' },
  { to: '/governance', icon: <Shield size={15}/>, label: 'Governance' },
  { to: '/packaging', icon: <Package size={15}/>, label: 'Packaging' },
]

const navTestId = (to: string) => (to === '/' ? 'nav-overview' : `nav-${to.slice(1).split('/').join('-')}`)

function NavItems({ items }: { items: NavItem[] }) {
  return (
    <>
      {items.map(n => (
        <NavLink
          key={n.to}
          to={n.to}
          end={n.to === '/'}
          data-testid={navTestId(n.to)}
          className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
        >
          {n.icon} {n.label}
        </NavLink>
      ))}
    </>
  )
}

/** Footer card: deployment mode and version (from the overview endpoint; fetched once, no polling). */
function ModeCard({ version }: { version: string }) {
  const q = useQuery({ queryKey: ['overview', '24h'], queryFn: () => getOverview('24h'), staleTime: 60_000 })
  const mode = q.data?.mode
  return (
    <div data-testid="mode-card" style={{ padding: '10px 12px', background: 'var(--bg-hover)', borderRadius: 'var(--radius-md)', fontSize: 11, marginBottom: 8 }}>
      <div data-testid="mode-label" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
        {mode === 'platform' ? 'Platform' : mode === 'standalone' ? 'Standalone · local only' : 'Mode unknown'}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text-secondary)', marginTop: 4 }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 6 }} data-testid="version-label">
          <Cpu size={12}/> AgentOS · v{q.data?.version ?? version}
        </span>
        <span style={{ color: 'var(--accent-teal)', display: 'flex', alignItems: 'center', gap: 4 }}>
          <Lock size={10} /> Authenticated
        </span>
      </div>
    </div>
  )
}

export default function App() {
  const [version, setVersion] = useState('2.0.0')
  const [classicOpen, setClassicOpen] = useState(false)
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(() => !!getAuthToken())

  useEffect(() => {
    // If URL hash had #token=..., getAuthToken() will have extracted and stored it
    const token = getAuthToken()
    if (token) {
      setIsAuthenticated(true)
    }

    if (isAuthenticated) {
      getHealth()
        .then(h => {
          if (h.version) {
            setVersion(h.version)
          }
        })
        .catch(err => console.error('Error fetching health/version:', err))
    }
  }, [isAuthenticated])

  if (!isAuthenticated) {
    return <AuthGate onAuthenticated={() => setIsAuthenticated(true)} />
  }

  const handleLogout = () => {
    clearAuthToken()
    setIsAuthenticated(false)
  }

  return (
    <BrowserRouter>
      <div className="app-shell">
        <aside className="sidebar">
          <div className="sidebar-logo">
            <h1>Agent<span style={{ color: 'var(--accent-brand)' }}>OS</span></h1>
            <p>Core Resource Management (v2)</p>
          </div>
          <nav className="sidebar-nav" data-testid="sidebar-nav">
            {NAV_GROUPS.map(g => (
              <div key={g.title} data-testid={`nav-group-${g.title.toLowerCase()}`}>
                <span className="nav-section">{g.title}</span>
                <NavItems items={g.items} />
              </div>
            ))}
            <button
              className="nav-section nav-section-toggle"
              data-testid="nav-classic-toggle"
              aria-expanded={classicOpen}
              onClick={() => setClassicOpen(o => !o)}
            >
              {classicOpen ? <ChevronDown size={11}/> : <ChevronRight size={11}/>} Classic (v1)
            </button>
            {classicOpen && <div data-testid="nav-group-classic"><NavItems items={CLASSIC} /></div>}
          </nav>
          <div style={{ padding: '0 12px', marginTop: 8 }}>
            <ModeCard version={version} />
            <button
              id="logout-btn"
              onClick={handleLogout}
              className="btn btn-ghost btn-sm"
              style={{ width: '100%', justifyContent: 'flex-start', color: 'var(--text-muted)', fontSize: 12, padding: '6px 8px' }}
            >
              <LogOut size={13}/> Lock / Change Token
            </button>
          </div>
        </aside>

        <main className="main-content">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/runs" element={<Runs />} />
            <Route path="/approvals" element={<Approvals />} />
            <Route path="/triggers" element={<Triggers />} />
            <Route path="/security" element={<SecurityLog />} />
            <Route path="/audit" element={<AuditLog />} />
            <Route path="/metrics" element={<Metrics />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/notifications" element={<NotificationChannels />} />
            <Route path="/classic/dashboard" element={<Dashboard />} />
            <Route path="/agents" element={<Agents />} />
            <Route path="/squads" element={<Squads />} />
            <Route path="/crews" element={<Squads />} /> {/* Backward compatibility alias */}
            <Route path="/tools" element={<Tools />} />
            <Route path="/mcp-servers" element={<MCPServers />} />
            <Route path="/providers" element={<Providers />} />
            <Route path="/missions" element={<Missions />} />
            <Route path="/templates" element={<Templates />} />
            <Route path="/runs/:runId" element={<RunDetail />} />
            <Route path="/builder" element={<Builder />} />
            <Route path="/flows" element={<Flows />} />
            <Route path="/flows/:flowId" element={<FlowEditor />} />
            <Route path="/governance" element={<Governance />} />
            <Route path="/packaging" element={<Packaging />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
