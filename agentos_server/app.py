"""
FastAPI app factory for the AgentOS backend server.

Usage:
    from agentos_server.app import create_app
    app = create_app(project_path="/path/to/my-project")
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

# Paths that are never answered with the UI (they keep their own 404s and handlers).
_NON_UI_PREFIXES = ("api", "hooks", "ws")


class SPAStaticFiles(StaticFiles):
    """2.4d-fix: built UI with a single-page-app fallback.

    A client route such as /flows/<id> (no file extension, not under /api, /hooks or /ws) is answered
    with index.html so deep links and reloads work in single-port mode. Real files are served as before;
    a missing asset (has an extension) and anything under /api, /hooks, /ws still 404. The Host and
    token checks run in SecurityMiddleware before this, unchanged.
    """

    async def get_response(self, path: str, scope):
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            rel = path.replace("\\", "/").strip("/")  # StaticFiles passes an OS path (backslashes on Windows)
            first = rel.split("/", 1)[0]
            last = rel.rsplit("/", 1)[-1]
            if exc.status_code != 404 or first in _NON_UI_PREFIXES or "." in last:
                raise
            return await super().get_response("index.html", scope)

from agentos_server.run_manager import RunManager
from agentos.core.governance import GovernanceEngine

logger = logging.getLogger(__name__)


from typing import Any, Optional

# 4.2: the admin config loaders live in agentos.core.admin_config (shared with the CLI); re-exported here.
from agentos.core.admin_config import (  # noqa: F401,E402
    INTERNAL_DOMAINS_ENV,
    load_internal_domains,
    HTTP_ALLOWLIST_ENV,
    load_http_allowlist,
    load_notifications_config,
    _security_section,
    load_allowlists,
    ALLOW_DECLASSIFIED_DESTRUCTIVE_ENV,
    ALLOW_EXTRACTION_DESTRUCTIVE_ENV,
    load_allow_declassified_for_destructive,
    load_separation_of_duties,
    load_allow_extraction_for_destructive,
    load_price_overrides,
)


def create_app(
    project_path: Optional[str] = None,
    storage: Optional[Any] = None,
) -> FastAPI:
    """
    Create and configure the AgentOS FastAPI application.

    Args:
        project_path: Optional absolute path to the AgentOS project directory.
        storage: Optional pre-configured Storage instance (File or Mongo).
    """
    from agentos.core.logging_config import setup_logging
    from agentos.__version__ import __version__
    setup_logging()

    if project_path is None:
        project_path = os.environ.get("AGENTOS_PROJECT", os.getcwd())
    project_path = os.path.abspath(project_path)

    # 3.5 (0a): with AGENTOS_FORBID_REAL_HOME=1, never start on a path inside the real ~/.agentos
    from agentos.core.home_guard import check_path, guard_enabled
    if guard_enabled():
        check_path(project_path, "project folder")
        from agentos.security.vault import default_master_key_path
        from agentos_server.auth import default_token_path
        if not os.environ.get("AGENTOS_MASTER_KEY"):
            default_master_key_path()
        if not os.environ.get("AGENTOS_API_TOKEN"):
            default_token_path()
        if storage is None:
            from agentos.storage.file import default_vault_path
            default_vault_path()
        if os.environ.get("AGENTOS_DATA_DIR"):
            check_path(os.environ["AGENTOS_DATA_DIR"], "AGENTOS_DATA_DIR")

    # Load API keys from .env (repo root first, then project directory overrides), in the one place that does
    # it. AGENTOS_SKIP_DOTENV=1 (e2e / screenshot servers): never load the developer's .env keys.
    from agentos.core.dotenv_loader import load_env_files
    load_env_files(project_path)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        from agentos.core.bootstrap import register_builtin_components
        register_builtin_components()
        logger.info(f"AgentOS API starting for project: {project_path}")

        # If Mongo URI is configured and storage was not explicitly provided, open Mongo storage
        mongo_uri = os.environ.get("AGENTOS_MONGO_URI")
        if mongo_uri and getattr(app.state, "_storage_explicit", False) is False:
            try:
                # 3.5 (0b): same resolver as the CLI (honours AGENTOS_MONGO_DB)
                from agentos.core.locations import open_app_storage
                app.state.storage = await open_app_storage(project_path)
                from agentos.security.vault import Vault
                app.state.vault = Vault(app.state.storage.credentials, app.state.master_key)
                if getattr(app.state, "mcp_manager", None) is not None:
                    app.state.mcp_manager.storage = app.state.storage
                app.state.queue.set_storage(app.state.storage)
                from agentos.audit import audit_anchor_for, audit_store_for
                app.state.audit.store = audit_store_for(app.state.storage)
                app.state.audit.anchor = audit_anchor_for(app.state.storage)
                from agentos.usage import usage_stores_for
                app.state.usage.ledger, app.state.usage.settings = usage_stores_for(app.state.storage)
                from agentos.access import access_store_for
                app.state.access.store = access_store_for(app.state.storage)
                from agentos.notify.store import notify_store_for
                app.state.notify.store = notify_store_for(app.state.storage)
                app.state.notify.storage = app.state.storage
                app.state.notify.vault = app.state.vault
                from agentos.sandbox.store import sandbox_settings_store_for
                app.state.sandbox.settings_store = sandbox_settings_store_for(app.state.storage)
                from agentos.review.store import review_store_for
                app.state.review = review_store_for(app.state.storage)
                if hasattr(app.state.storage.events, "_fencing_checker"):
                    app.state.storage.events._fencing_checker = app.state.queue.validate_lease
                # Use Mongo server-time leader lock in Platform mode
                from agentos.triggers.scheduler import MongoLeaderLock
                db = app.state.storage.runs._c.database
                if hasattr(app.state, "scheduler") and app.state.scheduler:
                    app.state.scheduler.leader_lock = MongoLeaderLock(db.leader_locks)
            except Exception as e:
                logger.error(f"Failed to connect to Mongo at {mongo_uri}: {e}")
                raise RuntimeError(
                    f"AGENTOS_MONGO_URI is set but MongoDB is unreachable at {mongo_uri}: {e}"
                ) from e

        # Pre-load fallback policy cache into in-memory router cache
        try:
            configs = await app.state.storage.provider_configs.list()
            from agentos.llm.router_factory import set_fallback_policy_cache
            set_fallback_policy_cache([c.model_dump() for c in configs])
        except Exception as e:
            logger.warning(f"Failed to pre-load fallback policy cache: {e}")

        # Requirement 2: Startup recovery: find runs whose last state is queued/running (from event log)
        # and re-enqueue them.
        try:
            if app.state.storage.flows:
                runs = await app.state.storage.runs.list(limit=1000)
                terminal_events = {"run_succeeded", "run_failed", "run_cancelled"}
                for r in runs:
                    if not r.flow_id:
                        continue
                    evs = await app.state.storage.events.list(r.run_id, after_seq=0)
                    ev_types = [e.type for e in evs]
                    is_terminal = any(t in terminal_events for t in ev_types)
                    is_waiting = any(t == "run_waiting" for t in ev_types)
                    if not is_terminal and not is_waiting:
                        start_ev = next((e for e in evs if e.type == "run_started"), None)
                        inputs = (start_ev.data or {}).get("inputs", {}) if start_ev else r.outputs
                        ver = r.flow_version or 1
                        await app.state.queue.reenqueue(
                            run_id=r.run_id,
                            flow_id=r.flow_id,
                            version=ver,
                            inputs=inputs,
                        )
                        logger.info("Startup recovery re-enqueued flow run %s", r.run_id)
        except Exception as e:
            logger.warning(f"Startup recovery failed: {e}")

        # Start cron trigger scheduler
        if hasattr(app.state, "scheduler") and app.state.scheduler:
            # Fails startup with a clear error if schedules exist but croniter is missing.
            await app.state.scheduler.ensure_cron_support()
            app.state.scheduler.start()

        # 2.4c: provider keys stored in the vault (named like GROQ_API_KEY) are used first.
        if getattr(app.state, "vault", None) is not None:
            try:
                from agentos.llm.provider_registry import export_vault_provider_keys

                loaded = await export_vault_provider_keys(app.state.vault)
                if loaded:
                    logger.info("Loaded provider keys from the vault: %s", ", ".join(loaded))
            except Exception as e:
                logger.warning("Could not load provider keys from the vault: %s", type(e).__name__)

        # 3.3: billing plans are cached on the usage context (price() is synchronous)
        try:
            await app.state.usage.get_settings()
        except Exception as e:
            logger.warning("Could not load usage settings: %s", type(e).__name__)

        # 3.3: notifications. Default alert rules (no channel), Slack channel names into the policy, outbox
        # recovery (an entry left "sending" is never resent), approval timers, the event observer, the worker.
        from agentos.notify.service import NotifyWorker, ObservedEvents
        notify = app.state.notify
        app.state.notify_worker = None
        try:
            await notify.ensure_default_rules()
            await notify.sync_policy()
            await notify.recover()
            await notify.reschedule_waiting()
            if not isinstance(app.state.storage.events, ObservedEvents):
                app.state.storage.events = ObservedEvents(app.state.storage.events, notify.on_event)
            app.state.notify_worker = NotifyWorker(notify)
            app.state.notify_worker.start()
        except Exception as e:
            logger.error("Notifications could not start: %s", type(e).__name__)
        try:
            await notify.on_audit_verify(await app.state.audit.verify())
        except Exception as e:
            logger.warning("Startup audit verification failed: %s", type(e).__name__)

        # 3.5: sandbox settings, leftover containers of a crashed server, old per-run workspaces
        try:
            await app.state.sandbox.get_settings()
            import asyncio as _aio_sb

            from agentos.sandbox.docker_backend import sweep_leftovers
            removed = await _aio_sb.to_thread(sweep_leftovers)
            swept = await _aio_sb.to_thread(app.state.sandbox.sweep)
            if removed or swept:
                logger.info("Sandbox: removed %d leftover container(s), %d old workspace(s)", removed, swept)
        except Exception as e:
            logger.warning("Sandbox start-up check failed: %s", type(e).__name__)

        # Opt-in in-process flow worker (Standalone): AGENTOS_INPROCESS_WORKER=1
        from agentos_server.inprocess_worker import InProcessFlowWorker, inprocess_worker_enabled
        app.state.inprocess_worker = None
        if inprocess_worker_enabled():
            app.state.inprocess_worker = InProcessFlowWorker(app)
            app.state.inprocess_worker.start()

        # 3.4: compute the dummy password hash for unknown-user logins in the background (equal login timing)
        import asyncio as _aio
        app.state.access_warm_task = _aio.create_task(app.state.access.warm())

        # Print where to log in (never the token itself)
        server_port = int(os.environ.get("AGENTOS_PORT", 8000))
        print_startup_auth_banner(app.state.api_token, server_port=server_port)

        # 3.1: startup + config entries (best effort: the server still starts if the audit store is down,
        # but every audited admin action then fails closed with 503)
        from agentos_server.audit_support import audit_shutdown, audit_startup
        mode = "platform" if getattr(app.state.storage, "backend", "file") == "mongo" else "standalone"
        await audit_startup(app, project_path, mode, __version__)

        # 3.6b: OpenTelemetry export if configured
        from agentos.telemetry import setup_telemetry
        setup_telemetry()

        yield
        await audit_shutdown(app, mode, __version__)
        # Stop the in-process worker before storage is closed
        if getattr(app.state, "inprocess_worker", None) is not None:
            await app.state.inprocess_worker.stop()
            app.state.inprocess_worker = None
        # 3.3: stop the notification worker (pending outbox entries are delivered after the next start)
        if getattr(app.state, "notify_worker", None) is not None:
            await app.state.notify_worker.stop()
            app.state.notify_worker = None
        # 2.5a: stop every MCP server child process (no orphans)
        if getattr(app.state, "mcp_manager", None) is not None:
            try:
                await app.state.mcp_manager.stop_all("shutdown")
            except Exception:
                logger.exception("Stopping MCP servers failed")
        # Stop scheduler
        if hasattr(app.state, "scheduler") and app.state.scheduler:
            try:
                await app.state.scheduler.stop()
            except Exception:
                pass
        # Close mongo client if present
        closer = getattr(app.state.storage, "_closer", None)
        if closer:
            try:
                await closer()
            except Exception:
                pass
        logger.info("AgentOS API shutting down.")

    app = FastAPI(
        title="AgentOS API",
        description="REST API for the AgentOS multi-agent framework",
        version=__version__,
        lifespan=lifespan,
    )

    # -----------------------------------------------------------------------
    # CORS — allow the Vite dev server (port 5173) and any localhost origin
    # -----------------------------------------------------------------------
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # -----------------------------------------------------------------------
    # App state — shared between all requests
    # -----------------------------------------------------------------------
    app.state.project_path = project_path
    gov = GovernanceEngine()
    gov.initialize_security_policies()
    app.state.governance = gov
    app.state.run_manager = RunManager(governance=gov)
    app.state.failed_providers = set()
    from agentos.flows.policy import SecurityPolicy
    # Trusted internal email domains are admin configuration (secure default: none trusted).
    app.state.security_policy = SecurityPolicy(
        internal_domains=load_internal_domains(project_path),
        http_allowlist=load_http_allowlist(project_path),
        allowlists=load_allowlists(project_path),
        allow_declassified_for_destructive=load_allow_declassified_for_destructive(project_path),
    )

    # Initialize 1.2 Storage port (File or Mongo)
    if storage is not None:
        app.state.storage = storage
        app.state._storage_explicit = True
    else:
        from agentos.storage.file import open_file_storage
        app.state.storage = open_file_storage(project_path)
        app.state._storage_explicit = False

    # Initialize QueueBackend & NonceCache (Redis for Platform mode, InProcess for Standalone)
    redis_uri = os.environ.get("AGENTOS_REDIS_URI") or os.environ.get("AGENTOS_REDIS_URL")
    if redis_uri:
        import redis.asyncio as aioredis
        from agentos.queue.redis import RedisQueueBackend
        from agentos.triggers.nonce_cache import RedisNonceCache
        redis_client = aioredis.from_url(redis_uri)
        app.state.redis = redis_client
        app.state.queue = RedisQueueBackend(redis_client, storage=app.state.storage)
        app.state.nonce_cache = RedisNonceCache(redis_client)
    else:
        from agentos.queue.in_process import InProcessQueueBackend
        from agentos.triggers.nonce_cache import InMemoryNonceCache
        app.state.queue = InProcessQueueBackend(storage=app.state.storage)
        app.state.nonce_cache = InMemoryNonceCache()

    if hasattr(app.state.storage.events, "_fencing_checker"):
        app.state.storage.events._fencing_checker = app.state.queue.validate_lease

    # Initialize Cron FlowScheduler
    from agentos.triggers.scheduler import FlowScheduler, InProcessLeaderLock
    app.state.scheduler = FlowScheduler(
        storage=app.state.storage,
        queue=app.state.queue,
        leader_lock=InProcessLeaderLock(),
    )

    # Initialize Credentials Vault
    from agentos.security.vault import Vault, MasterKey
    try:
        master_key = MasterKey.load(create=True)
    except Exception as e:
        raise RuntimeError(f"Failed to load vault master key: {e}") from e
    app.state.master_key = master_key
    # Fail closed on a damaged Standalone vault file (zero-filled, truncated, wrong master key):
    # never start, and never write a new empty vault over it. (vault incident 2026-11-18)
    from agentos.security.vault import VaultFileError, verify_vault_file
    from agentos.storage.file import JsonFileMapRepository
    creds = app.state.storage.credentials
    if isinstance(creds, JsonFileMapRepository):
        try:
            verify_vault_file(creds.path, master_key)
        except VaultFileError as e:
            raise RuntimeError(f"Vault check failed, AgentOS will not start: {e}") from e
    app.state.vault = Vault(app.state.storage.credentials, master_key)

    # 3.1: tamper-evident audit log (HMAC chain keyed from the master key; the key never leaves AuditLog).
    # The store follows the storage backend (rebound in the lifespan if Mongo replaces the file store).
    from agentos.audit import AuditLog, audit_anchor_for, audit_store_for
    from agentos_server.audit_support import AuthFailureAggregator, mcp_event_sink
    app.state.audit = AuditLog(audit_store_for(app.state.storage), master_key.key,
                               anchor=audit_anchor_for(app.state.storage))
    app.state.auth_failures = AuthFailureAggregator()

    # 3.4: users, sessions and API tokens (store follows the storage backend; rebound if Mongo replaces it).
    # The CSRF key is derived from the master key inside AccessService (never stored or returned).
    import asyncio as _asyncio

    from agentos.access import AccessService, access_store_for
    from agentos.access.ratelimit import LoginLimiter
    app.state.access = AccessService(access_store_for(app.state.storage), master_key.key)
    app.state.login_limiter = LoginLimiter()
    app.state.access_setup_lock = _asyncio.Lock()
    app.state.separation_of_duties = load_separation_of_duties(project_path)

    # 3.2: usage ledger, budgets and run limits (admin settings) + admin price overrides
    from agentos.usage import UsageContext, usage_stores_for
    _ledger, _usage_settings = usage_stores_for(app.state.storage)
    app.state.usage = UsageContext(_ledger, _usage_settings, load_price_overrides(project_path))

    # 3.3: notification channels, alerts and the flow transports for send_email / send_slack. A test (or an
    # embedding app) that sets app.state.transport_registry after create_app keeps its own.
    from agentos.notify.service import ChannelEmailTransport, ChannelSlackTransport, NotifyService
    from agentos.notify.store import notify_store_for
    _ncfg = load_notifications_config(project_path)
    app.state.notify = NotifyService(
        notify_store_for(app.state.storage), app.state.vault, storage=app.state.storage,
        smtp_allowlist=_ncfg["smtp_allowlist"], ui_base_url=_ncfg["ui_base_url"], policy=app.state.security_policy,
    )
    app.state.transport_registry = {"send_email": ChannelEmailTransport(app.state.notify),
                                    "send_slack": ChannelSlackTransport(app.state.notify)}

    # 3.5: sandbox for the code tools (python_exec / shell_exec / file_*). Fail closed without a backend; nothing
    # from this process (env, vault, keys) is passed into a sandbox. Settings follow the storage backend.
    from agentos.core.locations import data_dir
    from agentos.sandbox import SandboxService
    from agentos.sandbox.store import sandbox_settings_store_for
    app.state.sandbox = SandboxService(data_dir(), sandbox_settings_store_for(app.state.storage))

    # 3.6a: review queue and sampling store
    from agentos.review.store import review_store_for
    app.state.review = review_store_for(app.state.storage)

    # 2.5a: MCP servers (started on first use, stopped when idle and on shutdown). Secrets for a
    # server's secret_env come from the vault, resolved per server; http URLs use the admin allowlist.
    from agentos.mcp.manager import MCPManager

    app.state.mcp_manager = MCPManager(
        project_path=project_path,
        storage=app.state.storage,
        secret_resolver=lambda name: app.state.vault.reveal(name),
        url_allowlist=list(getattr(app.state.security_policy, "http_allowlist", []) or []),
        # 3.1: server lifecycle events go to the audit log (not the old mcp-server-<name> pseudo-run events)
        event_sink=mcp_event_sink(app),
    )

    # Local API token
    from agentos_server.auth import get_or_create_api_token, print_startup_auth_banner, SecurityMiddleware
    api_token = get_or_create_api_token()
    app.state.api_token = api_token

    # -----------------------------------------------------------------------
    # Security Middleware: Host header validation & Token Authentication (HTTP & WS)
    # -----------------------------------------------------------------------
    app.add_middleware(SecurityMiddleware, api_token=api_token)

    # -----------------------------------------------------------------------
    # Register API routes
    # -----------------------------------------------------------------------
    from agentos_server.routes.health import router as health_router
    from agentos_server.routes.agents import router as agents_router
    from agentos_server.routes.tools import router as tools_router
    from agentos_server.routes.crews import router as crews_router
    from agentos_server.routes.missions import router as missions_router
    from agentos_server.routes.runs import router as runs_router
    from agentos_server.routes.checkpoints import router as checkpoints_router
    from agentos_server.routes.builder import router as builder_router
    from agentos_server.routes.mcp_plugins import router as mcp_router
    from agentos_server.routes.governance import router as governance_router
    from agentos_server.routes.packaging import router as packaging_router
    from agentos_server.routes.templates import router as templates_router
    from agentos_server.routes.federation import router as federation_router
    from agentos_server.routes.providers import router as providers_router

    app.include_router(health_router, prefix="/api")
    app.include_router(agents_router, prefix="/api")
    app.include_router(tools_router, prefix="/api")
    app.include_router(crews_router, prefix="/api")
    app.include_router(missions_router, prefix="/api")
    app.include_router(runs_router, prefix="/api")
    app.include_router(checkpoints_router, prefix="/api")
    app.include_router(builder_router, prefix="/api")
    app.include_router(mcp_router, prefix="/api")
    app.include_router(governance_router, prefix="/api")
    app.include_router(packaging_router, prefix="/api")
    app.include_router(templates_router, prefix="/api")
    app.include_router(federation_router, prefix="/api")
    app.include_router(providers_router, prefix="/api")

    from agentos_server.routes_v2 import router as v2_router
    app.include_router(v2_router, prefix="/api/v2")

    from agentos_server.routes_hooks import router as hooks_router
    app.include_router(hooks_router)

    # -----------------------------------------------------------------------
    # Serve built frontend in production mode: packaged copy first (wheel
    # installs), then the ui/ build output (source checkouts).
    # -----------------------------------------------------------------------
    package_static = os.path.join(os.path.dirname(__file__), "static")
    checkout_dist = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ui", "dist")
    frontend_dist = package_static if os.path.isfile(os.path.join(package_static, "index.html")) else checkout_dist
    # 2.4c: the launcher points at a freshly built ui/dist explicitly (wins over an older packaged build).
    ui_override = os.environ.get("AGENTOS_UI_DIST")
    if ui_override and os.path.isfile(os.path.join(ui_override, "index.html")):
        frontend_dist = ui_override
    if os.path.exists(frontend_dist):
        app.mount("/", SPAStaticFiles(directory=frontend_dist, html=True), name="frontend")
        logger.info(f"Serving frontend from {frontend_dist}")

    return app
