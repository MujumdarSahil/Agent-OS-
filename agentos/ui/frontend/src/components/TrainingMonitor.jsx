/**
 * Training Monitor - List running jobs, logs
 */

import React, { useState } from 'react';

function TrainingMonitor({ apiToken }) {
  const [jobs, setJobs] = useState([]);

  return (
    <div>
      <h2 className="text-xl font-bold mb-4">Training Job Monitor</h2>
      <div className="bg-white p-4 rounded shadow">
        <p className="text-gray-600">Training jobs will appear here</p>
        <p className="text-sm text-gray-500 mt-2">WebSocket connection for real-time updates (stub)</p>
      </div>
    </div>
  );
}

export default TrainingMonitor;

