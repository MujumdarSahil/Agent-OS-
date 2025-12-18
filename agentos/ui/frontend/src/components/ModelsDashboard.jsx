/**
 * Models Dashboard - List models, show metrics, start training/quant
 */

import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_BASE = 'http://localhost:8000/api';

function ModelsDashboard({ apiToken }) {
  const [models, setModels] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadModels();
  }, []);

  const loadModels = async () => {
    try {
      const response = await axios.get(`${API_BASE}/models`, {
        headers: { Authorization: `Bearer ${apiToken}` }
      });
      if (response.data.success) {
        setModels(response.data.models);
      }
    } catch (error) {
      console.error('Error loading models:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div>Loading models...</div>;

  return (
    <div>
      <h2 className="text-xl font-bold mb-4">Models Dashboard</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {models.map((model) => (
          <div key={model.model_id} className="bg-white p-4 rounded shadow">
            <h3 className="font-semibold">{model.model_id}</h3>
            <p className="text-sm text-gray-600">Provider: {model.provider}</p>
            <p className="text-sm text-gray-600">Backend: {model.backend}</p>
            <p className="text-sm text-gray-600">Size: {model.size}</p>
            {model.quantized && (
              <span className="text-xs bg-green-100 text-green-800 px-2 py-1 rounded">Quantized</span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

export default ModelsDashboard;

