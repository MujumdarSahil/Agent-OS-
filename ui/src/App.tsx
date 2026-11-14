import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import { useState, useEffect } from 'react'
import {
  LayoutDashboard, Bot, Wrench, Users, Target,
  Wand2, Shield, Package, Cpu, LayoutGrid, Settings as SettingsIcon,
  Server, Key, Lock, LogOut
} from 'lucide-react'
import { getHealth, getAuthToken, clearAuthToken } from './api/client'
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

const NAV = [
  { to: '/', icon: <LayoutDashboard size={16}/>, label: 'Dashboard' },
  { to: '/agents', icon: <Bot size={16}/>, label: 'Agents' },
  { to: '/squads', icon: <Users size={16}/>, label: 'Squads' },
  { to: '/tools', icon: <Wrench size={16}/>, label: 'Tools' },
  { to: '/mcp-servers', icon: <Server size={16}/>, label: 'MCP Servers' },
  { to: '/providers', icon: <Key size={16}/>, label: 'Providers & Vault' },
  { to: '/missions', icon: <Target size={16}/>, label: 'Missions' },
  { to: '/templates', icon: <LayoutGrid size={16}/>, label: 'Templates' },
  { to: '/builder', icon: <Wand2 size={16}/>, label: 'Builder' },
  { to: '/governance', icon: <Shield size={16}/>, label: 'Governance' },
  { to: '/packaging', icon: <Package size={16}/>, label: 'Packaging' },
  { to: '/settings', icon: <SettingsIcon size={16}/>, label: 'Settings' },
]

export default function App() {
  const [version, setVersion] = useState('2.0.0')
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
            <h1>Agent<span style={{ color: '#8b5cf6' }}>OS</span></h1>
            <p>Core Resource Management (v2)</p>
          </div>
          <nav className="sidebar-nav">
            <span className="nav-section">Navigation</span>
            {NAV.map(n => (
              <NavLink
                key={n.to}
                to={n.to}
                end={n.to === '/'}
                className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
              >
                {n.icon} {n.label}
              </NavLink>
            ))}
          </nav>
          <div style={{ padding: '0 12px', marginTop: 'auto' }}>
            <div style={{ padding: '12px', background: 'var(--bg-hover)', borderRadius: 'var(--radius-md)', fontSize: 11, marginBottom: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text-secondary)' }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Cpu size={12}/> AgentOS · v{version}
                </span>
                <span style={{ color: '#10b981', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Lock size={10} /> Authenticated
                </span>
              </div>
            </div>
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
            <Route path="/" element={<Dashboard />} />
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
            <Route path="/governance" element={<Governance />} />
            <Route path="/packaging" element={<Packaging />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
