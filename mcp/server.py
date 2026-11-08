#!/usr/bin/env python3

import json
import sys
import os
import subprocess
import time

TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(TOOL_DIR)
BUILD_DIR = os.path.join(PROJECT_DIR, "build")
LOG_DIRS = ["/tmp/andrxpc", "/Library/Apple/usr/lib/andrxpc_logs"]


def read_message():
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        line = line.decode("utf-8").strip()
        if not line:
            break
        if ":" in line:
            key, val = line.split(":", 1)
            headers[key.strip()] = val.strip()

    length = int(headers.get("Content-Length", 0))
    if length == 0:
        return None

    body = sys.stdin.buffer.read(length)
    return json.loads(body.decode("utf-8"))


def send_message(msg):
    body = json.dumps(msg)
    encoded = body.encode("utf-8")
    sys.stdout.buffer.write(f"Content-Length: {len(encoded)}\r\n\r\n".encode("utf-8"))
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


def send_result(req_id, result):
    send_message({"jsonrpc": "2.0", "id": req_id, "result": result})


def send_error(req_id, code, message):
    send_message({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}})


def get_log_files():
    files = []
    for d in LOG_DIRS:
        if not os.path.isdir(d):
            continue
        for f in os.listdir(d):
            if not f.endswith(".xpc.log"):
                continue
            path = os.path.join(d, f)
            try:
                st = os.stat(path)
            except OSError:
                continue
            pid = 0
            proc = ""
            parts = f.replace(".xpc.log", "").split("_", 1)
            if len(parts) == 2:
                try:
                    pid = int(parts[0])
                except ValueError:
                    pass
                proc = parts[1]
            files.append({
                "path": path,
                "pid": pid,
                "process": proc,
                "size": st.st_size,
                "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime))
            })
    files.sort(key=lambda x: x.get("modified", ""), reverse=True)
    return files


def read_logs(filter_text=None, count=100, process=None, tag=None):
    lines = []
    for d in LOG_DIRS:
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if not f.endswith(".xpc.log"):
                continue
            parts = f.replace(".xpc.log", "").split("_", 1)
            pid = 0
            proc = ""
            if len(parts) == 2:
                try:
                    pid = int(parts[0])
                except ValueError:
                    pass
                proc = parts[1]

            if process and process.lower() not in proc.lower():
                continue

            path = os.path.join(d, f)
            try:
                with open(path, "r") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        if tag:
                            parts2 = line.split()
                            if len(parts2) >= 2 and parts2[1].upper() != tag.upper():
                                continue
                        if filter_text and filter_text.lower() not in line.lower():
                            continue
                        lines.append({"process": proc, "pid": pid, "message": line})
            except (IOError, PermissionError):
                pass

    return lines[-count:]


def get_status():
    files = get_log_files()
    total = 0
    processes = set()
    for f in files:
        processes.add(f["process"])
        try:
            with open(f["path"], "r") as fh:
                total += sum(1 for _ in fh)
        except (IOError, PermissionError):
            pass

    return {
        "log_files": len(files),
        "total_messages": total,
        "processes": sorted(list(processes)),
        "log_dirs": LOG_DIRS
    }


def do_inject(target, mode="dlopen"):
    injector = os.path.join(BUILD_DIR, "injector")
    dylib = os.path.join(BUILD_DIR, "xpchook.dylib")

    if not os.path.exists(injector):
        return {"error": "injector not found, run make first"}
    if not os.path.exists(dylib):
        return {"error": "xpchook.dylib not found, run make first"}

    if mode == "dlopen":
        try:
            int(target)
            cmd = ["sudo", injector, "-p", target, dylib]
        except ValueError:
            cmd = ["sudo", injector, "-n", target, dylib]
    elif mode == "restart":
        cmd = ["sudo", injector, "-r", target, dylib]
    elif mode == "daemon":
        cmd = ["sudo", injector, "-d", target, dylib]
    else:
        return {"error": f"unknown mode: {mode}"}

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {
            "command": " ".join(cmd),
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"error": "injection timed out"}
    except Exception as e:
        return {"error": str(e)}


def list_processes():
    injector = os.path.join(BUILD_DIR, "injector")
    if not os.path.exists(injector):
        return {"error": "injector not found, run make first"}

    try:
        result = subprocess.run(
            ["sudo", injector, "-l"],
            capture_output=True, text=True, timeout=15
        )
        return {"output": result.stdout, "exit_code": result.returncode}
    except Exception as e:
        return {"error": str(e)}


TOOLS = [
    {
        "name": "status",
        "description": "monitoring status - log file count, total intercepted messages, active processes",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "logs",
        "description": "read intercepted XPC messages from log files",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filter": {
                    "type": "string",
                    "description": "text filter, case-insensitive substring match"
                },
                "process": {
                    "type": "string",
                    "description": "filter by process name"
                },
                "tag": {
                    "type": "string",
                    "description": "filter by tag: INIT, CONN, SEND, RECV, REPLY, BOOT, NSXPC, CFMP, DNOTE, EVENT"
                },
                "count": {
                    "type": "integer",
                    "description": "number of recent messages to return (default 100)"
                }
            }
        }
    },
    {
        "name": "log_files",
        "description": "list active XPC log files with size and modification time",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "inject",
        "description": "inject xpchook.dylib into a process. requires root",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "process PID, name, or launchd label"
                },
                "mode": {
                    "type": "string",
                    "enum": ["dlopen", "restart", "daemon"],
                    "description": "dlopen = NSXPC only, restart = kill+relaunch with DYLD_INSERT, daemon = launchctl debug"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "processes",
        "description": "list all processes with PST task port status. requires root",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    }
]


def handle_request(msg):
    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params", {})

    if method == "initialize":
        send_result(req_id, {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "andrxpc", "version": "1.1.0"},
            "capabilities": {"tools": {}}
        })
    elif method == "notifications/initialized":
        pass
    elif method == "tools/list":
        send_result(req_id, {"tools": TOOLS})
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {})

        if name == "status":
            result = get_status()
        elif name == "logs":
            result = read_logs(
                filter_text=args.get("filter"),
                count=args.get("count", 100),
                process=args.get("process"),
                tag=args.get("tag")
            )
        elif name == "log_files":
            result = get_log_files()
        elif name == "inject":
            result = do_inject(
                target=args["target"],
                mode=args.get("mode", "dlopen")
            )
        elif name == "processes":
            result = list_processes()
        else:
            send_error(req_id, -32601, f"unknown tool: {name}")
            return

        send_result(req_id, {
            "content": [{"type": "text", "text": json.dumps(result, indent=2)}]
        })
    elif method == "ping":
        send_result(req_id, {})
    else:
        if req_id is not None:
            send_error(req_id, -32601, f"method not found: {method}")


def main():
    while True:
        msg = read_message()
        if msg is None:
            break
        handle_request(msg)


if __name__ == "__main__":
    main()
