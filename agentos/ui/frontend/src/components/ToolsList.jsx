/**
 * Tools List - List tools/MCPs and invoke
 */

import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_BASE = 'http://localhost:8000/api';

function ToolsList({ apiToken }) {
  const [tools, setTools] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadTools();
  }, []);

  const loadTools = async () => {
    try {
      const response = await axios.get(`${API_BASE}/tools`, {
        headers: { Authorization: `Bearer ${apiToken}` }
      });
      if (response.data.success) {
        setTools(response.data.tools);
      }
    } catch (error) {
      console.error('Error loading tools:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div>Loading tools...</div>;

  return (
    <div>
      <h2 className="text-xl font-bold mb-4">Tools & MCPs</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {tools.map((tool) => (
          <div key={tool.tool_id} className="bg-white p-4 rounded shadow">
            <h3 className="font-semibold">{tool.name}</h3>
            <p className="text-sm text-gray-600">{tool.description}</p>
            <p className="text-xs text-gray-500 mt-2">Domain: {tool.domain}</p>
            <p className="text-xs text-gray-500">MCP: {tool.mcp_id}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

export default ToolsList;

