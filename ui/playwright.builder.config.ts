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

// Vault incident 2026-11-18: the e2e server never sees the real ~/.agentos. Its whole home (HOME,
// USERPROFILE, Windows AppData) and every AgentOS path (vault, master key, token file, data dir) live in
// a fresh temp folder per run, next to the temp project. The vault there also holds webhook signing keys.
const SERVER_HOME = path.join(process.env.AGENTOS_E2E_PROJECT!, 'home')
for (const sub of ['.agentos', path.join('AppData', 'Local'), path.join('AppData', 'Roaming')]) {
  fs.mkdirSync(path.join(SERVER_HOME, sub), { recursive: true })
}
export const SERVER_HOME_ENV: Record<string, string> = {
  HOME: SERVER_HOME,
  USERPROFILE: SERVER_HOME,
  LOCALAPPDATA: path.join(SERVER_HOME, 'AppData', 'Local'),
  APPDATA: path.join(SERVER_HOME, 'AppData', 'Roaming'),
  AGENTOS_VAULT_PATH: path.join(SERVER_HOME, '.agentos', 'vault.json'),
  AGENTOS_MASTER_KEY_FILE: path.join(SERVER_HOME, '.agentos', 'master.key'),
  AGENTOS_API_TOKEN_FILE: path.join(SERVER_HOME, '.agentos', 'api.token'),
  AGENTOS_DATA_DIR: path.join(SERVER_HOME, 'data'),
  AGENTOS_MASTER_KEY: '', // a master key in the caller's environment is never used by the e2e server
  AGENTOS_SKIP_DOTENV: '1', // the developer's .env keys are never loaded (screenshots show a fresh install)
}
// Provider keys from the developer's own environment are blanked too: the MOCK e2e server never holds a
// real key, and screenshots never reveal which providers the developer has keys for. Names only are read
// from the registry source; no value is read or printed.
const registrySrc = fs.readFileSync(path.resolve(process.cwd(), '..', 'agentos', 'llm', 'provider_registry.py'), 'utf8')
for (const m of registrySrc.matchAll(/"(?:api_key_env|api_base_env)":\s*"([A-Z0-9_]+)"/g)) SERVER_HOME_ENV[m[1]] = ''
const realAgentos = path.join(os.homedir(), '.agentos').toLowerCase()
for (const [k, v] of Object.entries(SERVER_HOME_ENV)) {
  if (v && path.resolve(v).toLowerCase().startsWith(realAgentos)) throw new Error(`e2e server ${k} points into the real ~/.agentos`)
}
if (process.env.AGENTOS_E2E_PRINT_PATHS === '1') {
  // Resolved paths only, never file contents.
  for (const [k, v] of Object.entries(SERVER_HOME_ENV)) {
    if (k.startsWith('AGENTOS_') || ['HOME', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA'].includes(k)) {
      console.log(`e2e server ${k} = ${v || '(empty: not used)'}`)
    }
  }
  const blanked = Object.keys(SERVER_HOME_ENV).filter(k => !k.startsWith('AGENTOS_') && SERVER_HOME_ENV[k] === '').length
  console.log(`e2e server provider key/base variables blanked: ${blanked}`)
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
        ...SERVER_HOME_ENV, // never the real ~/.agentos (see above)
        AGENTOS_API_TOKEN: E2E_TOKEN,
        AGENTOS_MOCK_LLM: '1',
        // Opt-in in-process worker so UI-started runs execute (MockTransport: nothing is delivered).
        AGENTOS_INPROCESS_WORKER: '1',
        // Trusted internal domains are explicit admin config (secure default since the 2.0 cleanup: none).
        AGENTOS_INTERNAL_DOMAINS: 'corp.local',
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
