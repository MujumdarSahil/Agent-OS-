/**
 * AgentOS Frontend - Main App Component
 */

import React, { useState, useEffect } from 'react';
import ModelsDashboard from './components/ModelsDashboard';
import TrainingMonitor from './components/TrainingMonitor';
import ToolsList from './components/ToolsList';
import MissionsPage from './components/MissionsPage';
import SafetyMonitor from './components/SafetyMonitor';

const API_BASE = 'http://localhost:8000/api';

function App() {
  const [activeTab, setActiveTab] = useState('models');
  const [apiToken, setApiToken] = useState(localStorage.getItem('api_token') || '');

  useEffect(() => {
    if (apiToken) {
      localStorage.setItem('api_token', apiToken);
    }
  }, [apiToken]);

  return (
    <div className="min-h-screen bg-gray-100">
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <h1 className="text-2xl font-bold">AgentOS Dashboard</h1>
        </div>
      </header>

      <nav className="bg-white border-b">
        <div className="max-w-7xl mx-auto px-4">
          <div className="flex space-x-4">
            <button
              onClick={() => setActiveTab('models')}
              className={`px-4 py-2 ${activeTab === 'models' ? 'border-b-2 border-blue-500' : ''}`}
            >
              Models
            </button>
            <button
              onClick={() => setActiveTab('training')}
              className={`px-4 py-2 ${activeTab === 'training' ? 'border-b-2 border-blue-500' : ''}`}
            >
              Training
            </button>
            <button
              onClick={() => setActiveTab('tools')}
              className={`px-4 py-2 ${activeTab === 'tools' ? 'border-b-2 border-blue-500' : ''}`}
            >
              Tools & MCPs
            </button>
            <button
              onClick={() => setActiveTab('missions')}
              className={`px-4 py-2 ${activeTab === 'missions' ? 'border-b-2 border-blue-500' : ''}`}
            >
              Missions
            </button>
            <button
              onClick={() => setActiveTab('safety')}
              className={`px-4 py-2 ${activeTab === 'safety' ? 'border-b-2 border-blue-500' : ''}`}
            >
              Safety
            </button>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 py-8">
        {activeTab === 'models' && <ModelsDashboard apiToken={apiToken} />}
        {activeTab === 'training' && <TrainingMonitor apiToken={apiToken} />}
        {activeTab === 'tools' && <ToolsList apiToken={apiToken} />}
        {activeTab === 'missions' && <MissionsPage apiToken={apiToken} />}
        {activeTab === 'safety' && <SafetyMonitor apiToken={apiToken} />}
      </main>
    </div>
  );
}

export default App;

