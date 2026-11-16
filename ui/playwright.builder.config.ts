// Playwright config for the 2.4 visual builder specs (MOCK mode, real backend).
// Starts uvicorn (FileStorage in a temp project, AGENTOS_MOCK_LLM=1) and the Vite dev server,
// and Playwright stops both when the run ends.

import { defineConfig, devices } from '@playwright/test'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const API_PORT = Number(process.env.AGENTOS_E2E_API_PORT || 8765)
const UI_PORT = Number(process.env.AGENTOS_E2E_UI_PORT || 5174)
// Fixed, non-secret token used only by this throwaway e2e backend.
export const E2E_TOKEN = 'agentos-e2e-builder-token'

// Worker processes inherit this env from the main process, so the dir is created once.
if (!process.env.AGENTOS_E2E_PROJECT) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentos-e2e-'))
  fs.writeFileSync(path.join(dir, 'agentos.config.yaml'), 'preferred_tags: []\n', 'utf8')
  process.env.AGENTOS_E2E_PROJECT = dir
}

const python =
  process.env.AGENTOS_E2E_PYTHON ||
  (process.platform === 'win32' ? path.resolve(process.cwd(), '..', 'venv', 'Scripts', 'python.exe') : 'python')

export default defineConfig({
  testDir: './e2e',
  testMatch: /builder.*\.spec\.ts/,
  timeout: 60000,
  retries: 0,
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: `http://localhost:${UI_PORT}`,
    trace: 'retain-on-failure',
  },
  webServer: [
    {
      command: `"${python}" -m uvicorn agentos_server.app:create_app --factory --host 127.0.0.1 --port ${API_PORT}`,
      cwd: '..',
      url: `http://127.0.0.1:${API_PORT}/api/health`,
      reuseExistingServer: false,
      timeout: 120000,
      env: {
        AGENTOS_PROJECT: process.env.AGENTOS_E2E_PROJECT!,
        AGENTOS_API_TOKEN: E2E_TOKEN,
        AGENTOS_MOCK_LLM: '1',
        // Opt-in in-process worker so UI-started runs execute (MockTransport: nothing is delivered).
        AGENTOS_INPROCESS_WORKER: '1',
        AGENTOS_MONGO_URI: '',
        AGENTOS_REDIS_URI: '',
        AGENTOS_REDIS_URL: '',
      },
    },
    {
      command: `npm run dev -- --port ${UI_PORT} --strictPort`,
      url: `http://localhost:${UI_PORT}`,
      reuseExistingServer: false,
      timeout: 120000,
      env: { AGENTOS_API_TARGET: `http://127.0.0.1:${API_PORT}` },
    },
  ],
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
