#!/usr/bin/env python3
"""Verify that Codex discovers the complete Loomex MCP tool inventory.

This smoke starts the real ``codex app-server`` with an isolated CODEX_HOME.
It never starts a model turn or calls a Loomex tool, so it does not authenticate,
modify Runner state, or contact the Loomex backend. Marketplace mode exercises
the assembled plugin package; direct-binary mode is intended only for development.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, TextIO


EXPECTED_TOOL_COUNT = 33
REQUIRED_TOOLS = {
    "loomex_setup_status",
    "loomex_workflow_list",
    "loomex_human_open",
    "loomex_agent_task_list",
    "loomex_agent_task_respond",
}


class SmokeFailure(RuntimeError):
    """A deterministic discovery assertion or protocol operation failed."""


def _toml_string(value: str) -> str:
    # JSON string syntax is also valid TOML basic-string syntax.
    return json.dumps(value, ensure_ascii=False)


def _reader(stream: TextIO, output: queue.Queue[str | None]) -> None:
    try:
        for line in stream:
            output.put(line)
    finally:
        output.put(None)


def _stderr_reader(stream: TextIO, output: deque[str]) -> None:
    for line in stream:
        output.append(line.rstrip("\n"))


def _send(process: subprocess.Popen[str], message: dict[str, Any]) -> None:
    if process.stdin is None:
        raise SmokeFailure("codex app-server stdin is unavailable")
    process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
    process.stdin.flush()


def _receive_response(
    process: subprocess.Popen[str],
    output: queue.Queue[str | None],
    request_id: int,
    deadline: float,
    stderr_tail: deque[str],
) -> dict[str, Any]:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            diagnostics = "\n".join(stderr_tail) or "<empty>"
            raise SmokeFailure(
                f"timed out waiting for app-server response id={request_id}; "
                f"stderr tail:\n{diagnostics}"
            )
        try:
            line = output.get(timeout=remaining)
        except queue.Empty:
            continue
        if line is None:
            return_code = process.poll()
            diagnostics = "\n".join(stderr_tail) or "<empty>"
            raise SmokeFailure(
                f"codex app-server closed stdout (exit={return_code}) while waiting "
                f"for response id={request_id}; stderr tail:\n{diagnostics}"
            )
        try:
            message = json.loads(line)
        except json.JSONDecodeError as error:
            raise SmokeFailure(f"app-server emitted invalid JSON: {line.rstrip()!r}") from error
        if not isinstance(message, dict) or message.get("id") != request_id:
            # Notifications and unrelated responses are allowed while MCP startup runs.
            continue
        if "error" in message:
            raise SmokeFailure(
                f"app-server request id={request_id} failed: "
                f"{json.dumps(message['error'], sort_keys=True)}"
            )
        result = message.get("result")
        if not isinstance(result, dict):
            raise SmokeFailure(
                f"app-server response id={request_id} has no object result: {message!r}"
            )
        return result


def _assert_loomex_inventory(result: dict[str, Any], expected_version: str) -> None:
    data = result.get("data")
    if not isinstance(data, list):
        raise SmokeFailure("mcpServerStatus/list result.data must be an array")
    matches = [entry for entry in data if isinstance(entry, dict) and entry.get("name") == "loomex"]
    if len(matches) != 1:
        names = [entry.get("name") for entry in data if isinstance(entry, dict)]
        raise SmokeFailure(f"expected exactly one Loomex MCP server; discovered {names!r}")

    status = matches[0]
    server_info = status.get("serverInfo")
    if not isinstance(server_info, dict) or server_info.get("name") != "loomex":
        raise SmokeFailure(f"unexpected Loomex serverInfo: {server_info!r}")
    if server_info.get("version") != expected_version:
        raise SmokeFailure(
            f"expected Loomex serverInfo.version {expected_version!r}, "
            f"discovered {server_info.get('version')!r}"
        )

    tools = status.get("tools")
    if not isinstance(tools, dict):
        raise SmokeFailure("Loomex MCP status.tools must be an object")
    tool_names = set(tools)
    if len(tools) != EXPECTED_TOOL_COUNT:
        raise SmokeFailure(
            f"expected {EXPECTED_TOOL_COUNT} Loomex tools, discovered {len(tools)}: "
            f"{sorted(tool_names)!r}"
        )
    missing = REQUIRED_TOOLS - tool_names
    if missing:
        raise SmokeFailure(f"required Loomex tools are missing: {sorted(missing)!r}")


def _run_codex_json(
    codex: Path,
    arguments: list[str],
    environment: dict[str, str],
    timeout_seconds: float,
) -> Any:
    try:
        completed = subprocess.run(
            [str(codex), *arguments, "--json"],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise SmokeFailure(
            f"timed out running Codex command: {' '.join(arguments)}"
        ) from error
    if completed.returncode != 0:
        raise SmokeFailure(
            f"Codex command failed ({' '.join(arguments)}): "
            f"{completed.stderr.strip() or completed.stdout.strip() or '<empty>'}"
        )
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise SmokeFailure(
            f"Codex command emitted invalid JSON ({' '.join(arguments)}): "
            f"{completed.stdout.strip()!r}"
        ) from error


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SmokeFailure(f"cannot read {label} at {path}: {error}") from error
    if not isinstance(value, dict):
        raise SmokeFailure(f"{label} must contain a JSON object: {path}")
    return value


def _marketplace_contract(marketplace_root: Path) -> tuple[str, str]:
    marketplace = _read_json_object(
        marketplace_root / ".agents/plugins/marketplace.json", "marketplace manifest"
    )
    marketplace_name = marketplace.get("name")
    if marketplace_name != "loomex":
        raise SmokeFailure(
            f"assembled marketplace name must be 'loomex', found {marketplace_name!r}"
        )
    plugins = marketplace.get("plugins")
    if not isinstance(plugins, list):
        raise SmokeFailure("marketplace manifest plugins must be an array")
    entries = [
        entry
        for entry in plugins
        if isinstance(entry, dict) and entry.get("name") == "loomex"
    ]
    if len(entries) != 1:
        raise SmokeFailure("marketplace must contain exactly one Loomex plugin entry")

    plugin = _read_json_object(
        marketplace_root / "plugins/loomex/.codex-plugin/plugin.json",
        "Loomex plugin manifest",
    )
    version = plugin.get("version")
    if not isinstance(version, str) or not version:
        raise SmokeFailure("Loomex plugin manifest must declare a non-empty version")
    return marketplace_name, version


def _assert_installed_plugin(inventory: Any, expected_version: str) -> None:
    if not isinstance(inventory, dict) or not isinstance(inventory.get("installed"), list):
        raise SmokeFailure("codex plugin list returned an invalid installed inventory")
    matches = [
        plugin
        for plugin in inventory["installed"]
        if isinstance(plugin, dict) and plugin.get("pluginId") == "loomex@loomex"
    ]
    if len(matches) != 1:
        raise SmokeFailure(
            f"expected one installed loomex@loomex plugin, found {len(matches)}"
        )
    plugin = matches[0]
    if plugin.get("version") != expected_version:
        raise SmokeFailure(
            f"expected installed Loomex version {expected_version!r}, "
            f"found {plugin.get('version')!r}"
        )
    if plugin.get("installed") is not True or plugin.get("enabled") is not True:
        raise SmokeFailure(f"installed Loomex plugin is not enabled: {plugin!r}")


def run_smoke(
    codex: Path,
    expected_version: str,
    timeout_seconds: float,
    *,
    marketplace_root: Path | None = None,
    loomex_mcp: Path | None = None,
    mcp_cwd: Path | None = None,
) -> None:
    with tempfile.TemporaryDirectory(prefix="loomex-codex-discovery-") as temporary:
        root = Path(temporary)
        codex_home = root / "codex-home"
        isolated_home = root / "home"
        loomex_runtime = root / "loomex-runtime"
        codex_home.mkdir()
        isolated_home.mkdir()
        loomex_runtime.mkdir()
        environment = os.environ.copy()
        environment["CODEX_HOME"] = str(codex_home)
        environment["HOME"] = str(isolated_home)
        environment["LOOMEX_RUNTIME_DIR"] = str(loomex_runtime)
        environment.pop("OPENAI_API_KEY", None)
        environment.pop("CODEX_API_KEY", None)

        if marketplace_root is not None:
            _run_codex_json(
                codex,
                ["plugin", "marketplace", "add", str(marketplace_root)],
                environment,
                timeout_seconds,
            )
            _run_codex_json(
                codex,
                ["plugin", "add", "loomex@loomex"],
                environment,
                timeout_seconds,
            )
            inventory = _run_codex_json(
                codex,
                ["plugin", "list", "--available"],
                environment,
                timeout_seconds,
            )
            _assert_installed_plugin(inventory, expected_version)
        else:
            if loomex_mcp is None or mcp_cwd is None:
                raise SmokeFailure("direct-binary mode requires a binary and MCP cwd")
            (codex_home / "config.toml").write_text(
                "[mcp_servers.loomex]\n"
                f"command = {_toml_string(str(loomex_mcp))}\n"
                "args = []\n"
                f"cwd = {_toml_string(str(mcp_cwd))}\n"
                f"startup_timeout_sec = {max(1, int(timeout_seconds))}\n",
                encoding="utf-8",
            )

        process = subprocess.Popen(
            [str(codex), "app-server", "--listen", "stdio://"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=environment,
        )
        assert process.stdout is not None
        assert process.stderr is not None
        output: queue.Queue[str | None] = queue.Queue()
        stderr_tail: deque[str] = deque(maxlen=100)
        threading.Thread(target=_reader, args=(process.stdout, output), daemon=True).start()
        threading.Thread(
            target=_stderr_reader, args=(process.stderr, stderr_tail), daemon=True
        ).start()

        try:
            deadline = time.monotonic() + timeout_seconds
            _send(
                process,
                {
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "clientInfo": {
                            "name": "loomex-codex-mcp-discovery-smoke",
                            "version": "1.0.0",
                        },
                        "capabilities": {"experimentalApi": True},
                    },
                },
            )
            _receive_response(process, output, 1, deadline, stderr_tail)
            _send(process, {"method": "initialized", "params": {}})
            _send(
                process,
                {
                    "id": 2,
                    "method": "mcpServerStatus/list",
                    "params": {"detail": "toolsAndAuthOnly", "limit": 100},
                },
            )
            status = _receive_response(process, output, 2, deadline, stderr_tail)
            _assert_loomex_inventory(status, expected_version)
        finally:
            if process.stdin is not None:
                try:
                    process.stdin.close()
                except OSError:
                    pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)


def _executable_path(value: str, label: str) -> Path:
    candidate = shutil.which(value) if os.sep not in value else value
    if candidate is None:
        raise SmokeFailure(f"{label} executable was not found: {value}")
    path = Path(candidate).expanduser().resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise SmokeFailure(f"{label} is not an executable file: {path}")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--marketplace-root",
        help="assembled marketplace root to install and test through Codex (release mode)",
    )
    mode.add_argument(
        "--loomex-mcp",
        help="loomex-mcp binary to test directly (development mode only)",
    )
    parser.add_argument(
        "--codex",
        default="codex",
        help="Codex CLI executable (default: codex from PATH)",
    )
    parser.add_argument(
        "--mcp-cwd",
        default=str(Path(__file__).resolve().parent.parent),
        help="working directory configured for loomex-mcp (default: repository root)",
    )
    parser.add_argument(
        "--expected-version",
        help="exact expected plugin/server version; marketplace mode also verifies its manifest",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=30.0,
        help="overall initialize and discovery deadline (default: 30)",
    )
    arguments = parser.parse_args()
    if arguments.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be greater than zero")

    try:
        codex = _executable_path(arguments.codex, "Codex CLI")
        if arguments.marketplace_root:
            marketplace_root = Path(arguments.marketplace_root).expanduser().resolve(strict=True)
            if not marketplace_root.is_dir():
                raise SmokeFailure(f"marketplace root is not a directory: {marketplace_root}")
            _, manifest_version = _marketplace_contract(marketplace_root)
            expected_version = arguments.expected_version or manifest_version
            if expected_version != manifest_version:
                raise SmokeFailure(
                    f"expected version {expected_version!r} differs from assembled "
                    f"plugin manifest version {manifest_version!r}"
                )
            run_smoke(
                codex,
                expected_version,
                arguments.timeout_seconds,
                marketplace_root=marketplace_root,
            )
            mode_label = "assembled marketplace"
        else:
            if not arguments.expected_version:
                raise SmokeFailure("direct-binary mode requires --expected-version")
            loomex_mcp = _executable_path(arguments.loomex_mcp, "loomex-mcp")
            mcp_cwd = Path(arguments.mcp_cwd).expanduser().resolve(strict=True)
            if not mcp_cwd.is_dir():
                raise SmokeFailure(f"MCP working directory is not a directory: {mcp_cwd}")
            run_smoke(
                codex,
                arguments.expected_version,
                arguments.timeout_seconds,
                loomex_mcp=loomex_mcp,
                mcp_cwd=mcp_cwd,
            )
            mode_label = "direct development binary"
    except (OSError, SmokeFailure) as error:
        print(f"codex MCP discovery smoke failed: {error}", file=sys.stderr)
        return 1

    print(
        f"codex MCP discovery smoke passed ({mode_label}): Loomex serverInfo, "
        f"{EXPECTED_TOOL_COUNT} tools, and required setup/workflow/agent tools discovered"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
