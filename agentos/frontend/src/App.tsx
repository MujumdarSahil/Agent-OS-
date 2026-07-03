import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import { useState, useEffect } from 'react'
import {
  LayoutDashboard, Bot, Wrench, Users, Target,
  Wand2, Shield, Package, Cpu, LayoutGrid, Settings as SettingsIcon
} from 'lucide-react'
import { getHealth } from './api/client'
import Dashboard from './pages/Dashboard'
import Agents from './pages/Agents'
import Tools from './pages/Tools'
import Crews from './pages/Crews'
import Missions from './pages/Missions'
import RunDetail from './pages/RunDetail'
import Builder from './pages/Builder'
import Governance from './pages/Governance'
import Packaging from './pages/Packaging'
import Templates from './pages/Templates'
import Settings from './pages/Settings'

const NAV = [
  { to: '/', icon: <LayoutDashboard size={16}/>, label: 'Dashboard' },
  { to: '/templates', icon: <LayoutGrid size={16}/>, label: 'Templates' },
  { to: '/agents', icon: <Bot size={16}/>, label: 'Agents' },
  { to: '/tools', icon: <Wrench size={16}/>, label: 'Tools' },
  { to: '/crews', icon: <Users size={16}/>, label: 'Crews' },
  { to: '/missions', icon: <Target size={16}/>, label: 'Missions' },
  { to: '/builder', icon: <Wand2 size={16}/>, label: 'Builder' },
  { to: '/governance', icon: <Shield size={16}/>, label: 'Governance' },
  { to: '/packaging', icon: <Package size={16}/>, label: 'Packaging' },
  { to: '/settings', icon: <SettingsIcon size={16}/>, label: 'Settings' },
]

export default function App() {
  const [version, setVersion] = useState('0.2.0')

  useEffect(() => {
    getHealth()
      .then(h => {
        if (h.version) {
          setVersion(h.version)
        }
      })
      .catch(err => console.error('Error fetching version:', err))
  }, [])

  return (
    <BrowserRouter>
      <div className="app-shell">
        <aside className="sidebar">
          <div className="sidebar-logo">
            <h1>Agent<span style={{ color: '#8b5cf6' }}>OS</span></h1>
            <p>Multi-Agent Framework</p>
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
            <div style={{ padding: '12px', background: 'var(--bg-hover)', borderRadius: 'var(--radius-md)', fontSize: 11 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-secondary)' }}>
                <Cpu size={12}/> AgentOS · v{version}
              </div>
            </div>
          </div>
        </aside>

        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/templates" element={<Templates />} />
            <Route path="/agents" element={<Agents />} />
            <Route path="/tools" element={<Tools />} />
            <Route path="/crews" element={<Crews />} />
            <Route path="/missions" element={<Missions />} />
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
