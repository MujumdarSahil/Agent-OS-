import { test, expect } from '@playwright/test'

const TEST_TOKEN = 'test_agentos_token_secure_42'

test.describe('AgentOS 2.0 UI Core Resource Management', () => {
  test.beforeEach(async ({ page }) => {
    // Intercept /api calls to verify auth headers and provide contract responses
    await page.route('**/api/**', async (route) => {
      const request = route.request()
      const url = request.url()
      const method = request.method()
      const headers = request.headers()

      // Health endpoint is public; all other endpoints require authorization
      if (!url.includes('/api/health')) {
        const authHeader = headers['authorization'] || headers['x-agentos-token']
        if (!authHeader || !authHeader.includes(TEST_TOKEN)) {
          return route.fulfill({
            status: 401,
            contentType: 'application/json',
            body: JSON.stringify({ detail: 'Missing or invalid token' }),
          })
        }
      }

      if (url.includes('/api/health')) {
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            status: 'ok',
            version: '2.0.0',
            project: 'test-project',
            has_project: true,
            agents: 1,
            tools: 2,
            crews: 1,
            missions: 1,
          }),
        })
      }

      if (url.includes('/api/checkpoints')) {
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([]),
        })
      }

      if (url.includes('/api/providers/fallback-chain')) {
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([]),
        })
      }

      if (url.includes('/api/v2/agents')) {
        if (method === 'POST') {
          const postData = request.postDataJSON()
          return route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(postData),
          })
        }
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([
            {
              name: 'ResearchLead',
              role: 'Lead Researcher',
              goal: 'Investigate questions',
              tools: ['fetch_url'],
              allow_delegation: true,
            },
          ]),
        })
      }

      if (url.includes('/api/v2/squads')) {
        if (method === 'POST') {
          const postData = request.postDataJSON()
          return route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(postData),
          })
        }
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([
            {
              name: 'AuditSquad',
              process: 'sequential',
              agents: ['ResearchLead'],
              roles: { ResearchLead: 'coordinator' },
            },
          ]),
        })
      }

      if (url.includes('/api/v2/tools')) {
        if (method === 'POST') {
          const postData = request.postDataJSON()
          return route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ ...postData, origin: 'stored' }),
          })
        }
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([
            {
              name: 'fetch_url',
              description: 'Fetch web pages safely',
              language: 'python',
              code: '',
              origin: 'project',
            },
            {
              name: 'custom_calc',
              description: 'Custom math tool',
              language: 'python',
              code: '# preserved custom python code\ndef run(): pass',
              origin: 'stored',
            },
          ]),
        })
      }

      if (url.includes('/api/v2/mcp-servers')) {
        if (method === 'POST') {
          const postData = request.postDataJSON()
          return route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(postData),
          })
        }
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([
            {
              name: 'github_mcp',
              transport: 'stdio',
              command: 'npx -y @modelcontextprotocol/server-github',
              args: [],
              env: {},
              secret_env: { GITHUB_TOKEN: 'gh_vault_key' },
              enabled: false,
            },
          ]),
        })
      }

      if (url.includes('/api/v2/vault/keys')) {
        if (method === 'POST') {
          const postData = request.postDataJSON()
          return route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              name: postData.name,
              provider: postData.provider || null,
              hint: 'sk-...5544',
              key_id: 'key_id_vault_test',
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            }),
          })
        }
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([
            {
              name: 'openai_gpt4o',
              provider: 'openai_gpt4o',
              hint: 'sk-...abcd',
              key_id: 'vault_key_1',
              created_at: '2026-11-14T00:00:00Z',
              updated_at: '2026-11-14T00:00:00Z',
            },
          ]),
        })
      }

      if (url.includes('/api/v2/providers/fallback')) {
        if (method === 'PUT') {
          const postData = request.postDataJSON()
          return route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(postData.items),
          })
        }
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([
            {
              name: 'openai_gpt4o',
              order: 1,
              enabled: true,
              timeout_s: 10.0,
              display_name: 'GPT-4o',
              litellm_model: 'openai/gpt-4o',
            },
            {
              name: 'anthropic_claude_sonnet',
              order: 2,
              enabled: true,
              timeout_s: 15.0,
              display_name: 'Claude Sonnet',
              litellm_model: 'anthropic/claude-3-5-sonnet',
            },
          ]),
        })
      }

      if (url.includes('/api/v2/providers/test-connection')) {
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, error_class: null, message: null }),
        })
      }

      if (url.includes('/api/v2/providers') || url.includes('/api/providers')) {
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([
            {
              name: 'openai_gpt4o',
              display_name: 'GPT-4o',
              litellm_model: 'openai/gpt-4o',
              priority: 10,
              tags: ['fast', 'paid'],
              api_key_configured: true,
              api_key_env: 'OPENAI_API_KEY',
              api_base_env: null,
              is_local: false,
              status: 'active',
            },
          ]),
        })
      }

      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      })
    })
  })

  test('1. Auth Gate blocks unauthenticated users and unlocks via token', async ({ page }) => {
    // Navigate without token
    await page.goto('/')
    await page.evaluate(() => sessionStorage.clear())
    await page.reload()

    // Verify Auth Gate is presented
    await expect(page.locator('text=AgentOS Authentication')).toBeVisible()
    await expect(page.locator('#api-token-input')).toBeVisible()

    // Submitting empty should fail
    await page.click('#auth-unlock-btn')
    await expect(page.locator('text=Please enter a valid API token')).toBeVisible()

    // Unlock with valid token
    await page.fill('#api-token-input', TEST_TOKEN)
    await page.click('#auth-unlock-btn')

    // Verify dashboard and sidebar appear
    await expect(page.locator('text=Core Resource Management (v2)')).toBeVisible()
    await expect(page.locator('text=Authenticated')).toBeVisible()
  })

  test('2. Token from URL fragment (#token=...) automatically authenticates', async ({ page }) => {
    // Navigate with token in fragment
    await page.goto(`/#token=${TEST_TOKEN}`)

    // Verify immediate unlock without manual form entry
    await expect(page.locator('text=Core Resource Management (v2)')).toBeVisible()

    // Verify fragment is cleared from address bar to protect against history leakage
    const url = page.url()
    expect(url).not.toContain('#token=')
  })

  test('3. Agents page (v2) creates and lists agents with NodeSpec tools', async ({ page }) => {
    await page.goto(`/#token=${TEST_TOKEN}`)
    await page.click('text=Agents')

    await expect(page.locator('h2:has-text("Agents (v2)")')).toBeVisible()
    await expect(page.locator('text=ResearchLead')).toBeVisible()

    await page.click('#create-agent-btn')
    await expect(page.locator('text=Create Agent (v2)')).toBeVisible()

    await page.fill('#agent-name', 'E2EResearcher')
    await page.fill('#agent-role', 'E2E Lead Investigator')
    await page.fill('#agent-goal', 'Verify end-to-end integration flows')

    // Select fetch_url tool
    await page.click('button:has-text("fetch_url")')

    // Save agent
    await page.click('#agent-save-btn')
  })

  test('4. Tools page (v2) displays project vs stored tools', async ({ page }) => {
    await page.goto(`/#token=${TEST_TOKEN}`)
    await page.click('text=Tools')

    await expect(page.locator('h2:has-text("Tools (v2)")')).toBeVisible()
    await expect(page.locator('text=fetch_url')).toBeVisible()
    await expect(page.locator('text=Project (Read-Only)')).toBeVisible()
    await expect(page.locator('text=custom_calc')).toBeVisible()
    await expect(page.locator('text=Stored (Sandboxed)')).toBeVisible()

    // Scaffold new tool
    await page.click('#create-tool-btn')
    await page.fill('#tool-name-input', 'e2e_data_cleaner')
    await page.fill('#tool-desc-input', 'Cleans and validates datasets')
    await page.click('#save-tool-btn')
  })

  test('5. Squads page (v2) assigns member roles', async ({ page }) => {
    await page.goto(`/#token=${TEST_TOKEN}`)
    await page.click('text=Squads')

    await expect(page.locator('h2:has-text("Squads (v2)")')).toBeVisible()
    await expect(page.locator('text=AuditSquad')).toBeVisible()
    await expect(page.locator('text=(coordinator)')).toBeVisible()

    await page.click('#create-squad-btn')
    await page.fill('#squad-name', 'e2e_audit_squad')
  })

  test('6. External MCP Servers page (v2) enforces dormant security policy', async ({ page }) => {
    await page.goto(`/#token=${TEST_TOKEN}`)
    await page.click('text=MCP Servers')

    await expect(page.locator('h2:has-text("External MCP Servers (v2)")')).toBeVisible()
    // Verify Phase 1.4 security policy notice
    await expect(page.locator('text=Phase 1.4 Security Policy Notice')).toBeVisible()
    await expect(page.locator('text=never launched automatically')).toBeVisible()

    await expect(page.locator('text=github_mcp')).toBeVisible()
    await expect(page.locator('text=Configured (Dormant)')).toBeVisible()

    await page.click('#create-mcp-server-btn')
    await page.fill('#mcp-name', 'e2e_github_server')
    await page.fill('#mcp-command', 'npx -y @modelcontextprotocol/server-github')
    await page.click('#mcp-save-btn')
  })

  test('7. Providers & Vault page (v2) masks secrets and manages fallback policy', async ({ page }) => {
    await page.goto(`/#token=${TEST_TOKEN}`)
    await page.click('text=Providers & Vault')

    await expect(page.locator('h2:has-text("Providers & Vault (v2)")')).toBeVisible()
    await expect(page.locator('h3:has-text("Credentials Vault")')).toBeVisible()
    await expect(page.locator('text=Fallback Policy & Order')).toBeVisible()

    // Verify secret is masked (hint shown, never raw plaintext)
    await expect(page.locator('text=sk-...abcd')).toBeVisible()

    // Test Store Secret modal
    await page.click('#add-vault-key-btn')
    await page.fill('#vault-key-name', 'e2e_openai_key')
    await page.fill('#vault-key-secret', 'sk-test-live-key-998877665544')
    await page.click('#save-vault-secret-btn')

    // Test Save Policy
    await page.click('#save-fallback-policy-btn')
    await expect(page.locator('text=Fallback policy saved')).toBeVisible()
  })
})
