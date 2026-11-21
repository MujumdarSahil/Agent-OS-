"""wasm sandbox child process (3.5, D5). Runs ONLY the pinned CPython WASI build inside wasmtime.

Started by ``agentos.sandbox.wasm_backend`` as ``python -I <this file>`` with a minimal environment (it imports only
the standard library and wasmtime, never agentos). It reads one JSON spec on stdin and prints one JSON result on
stdout. The guest gets: one preopened directory (the per-call workspace) as /workspace, an empty environment, a fixed
argv, no sockets (WASI preview1), a memory limit, and epoch interruption for the time limit. A watcher stops the guest
when stdout/stderr or the workspace exceed their caps. The parent kills this process if it outlives the time limit.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time


def _dir_size(root: str) -> int:
    total = 0
    for dirpath, _dirs, names in os.walk(root, followlinks=False):
        for n in names:
            try:
                total += os.lstat(os.path.join(dirpath, n)).st_size
            except OSError:
                pass
    return total


def main() -> int:
    spec = json.loads(sys.stdin.read())
    import wasmtime as w

    cfg = w.Config()
    cfg.epoch_interruption = True
    engine = w.Engine(cfg)
    cache = spec.get("cache")
    module = None
    if cache and os.path.isfile(cache):
        try:
            module = w.Module.deserialize_file(engine, cache)
        except Exception:
            module = None
    if module is None:
        module = w.Module.from_file(engine, spec["wasm"])
        if cache:
            try:
                tmp = cache + ".tmp"
                with open(tmp, "wb") as fh:
                    fh.write(module.serialize())
                os.replace(tmp, cache)
            except OSError:
                pass

    linker = w.Linker(engine)
    linker.define_wasi()
    store = w.Store(engine)
    store.set_limits(memory_size=int(spec["memory_bytes"]))
    store.set_epoch_deadline(1)

    state = {"reason": None}
    caps = {"stdout": int(spec["stdout_cap"]), "stderr": int(spec["stderr_cap"])}
    bufs = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = {"stdout": False, "stderr": False}
    lock = threading.Lock()

    def stop(reason: str) -> None:
        with lock:
            if state["reason"] is None:
                state["reason"] = reason
        engine.increment_epoch()

    def sink(name: str):
        def write(data: bytes) -> None:
            buf = bufs[name]
            room = caps[name] - len(buf)
            if room > 0:
                buf.extend(data[:room])
            if len(data) > room:
                truncated[name] = True
                stop("output")
        return write

    wasi = w.WasiConfig()
    wasi.argv = ["python", "-I", "-S", "/workspace/" + spec["main"]] if spec.get("main") else ["python", "-I", "-S"]
    wasi.env = []
    wasi.stdout_custom = sink("stdout")
    wasi.stderr_custom = sink("stderr")
    wasi.preopen_dir(spec["workspace"], "/workspace")
    store.set_wasi(wasi)
    instance = linker.instantiate(store, module)

    done = threading.Event()

    def watch() -> None:
        deadline = time.monotonic() + float(spec["timeout_s"])
        cap = int(spec["workspace_cap"])
        while not done.wait(0.1):
            if time.monotonic() >= deadline:
                stop("timeout")
                return
            if _dir_size(spec["workspace"]) > cap:
                stop("workspace")
                return

    watcher = threading.Thread(target=watch, daemon=True)
    started = time.monotonic()
    watcher.start()
    exit_code = None
    trap = None
    try:
        instance.exports(store)["_start"](store)
        exit_code = 0
    except w.ExitTrap as e:
        exit_code = e.code
    except w.Trap as e:
        trap = str(e).splitlines()[0][:200]
    except Exception as e:  # wasmtime error (e.g. memory limit at instantiation)
        trap = f"{type(e).__name__}: {str(e).splitlines()[0][:200] if str(e) else ''}"
    finally:
        done.set()
    duration = (time.monotonic() - started) * 1000

    mem_bytes = 0
    try:
        mem = instance.exports(store).get("memory")
        if mem is not None:
            mem_bytes = mem.data_len(store)
    except Exception:
        pass
    reason = state["reason"]
    stderr_text = bufs["stderr"].decode("utf-8", "replace")
    if reason is None and exit_code not in (0, None):
        limit = int(spec["memory_bytes"])
        # inferred: the guest's allocation failed at the store limit (MemoryError) or memory is at the limit
        if mem_bytes >= limit - (8 << 20) or stderr_text.rstrip().endswith("MemoryError"):
            reason = "memory"
    print(json.dumps({
        "exit_code": exit_code, "trap": trap, "limit_hit": reason, "duration_ms": duration,
        "stdout": bufs["stdout"].decode("utf-8", "replace"), "stderr": stderr_text,
        "stdout_truncated": truncated["stdout"], "stderr_truncated": truncated["stderr"], "memory_bytes": mem_bytes,
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
