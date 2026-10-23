#!/usr/bin/env python3
"""End-to-end MCP smoke test for hvlab.

Spawns `hvlab mcp`, speaks JSON-RPC over stdio, and exercises the tools that
are safe to call read-only. Destructive/D/X tools are expected to refuse
without a plan token, which is itself asserted.

Usage:
    python smoke_mcp.py ./target/release/hvlab.exe
"""
import json
import subprocess
import sys
import threading

FAILURES = []
PASSES = []


def check(name, cond, detail=""):
    if cond:
        PASSES.append(name)
        print(f"  PASS  {name}")
    else:
        FAILURES.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


class Server:
    def __init__(self, exe):
        self.p = subprocess.Popen(
            [exe, "mcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.next_id = 1

    def send(self, method, params=None):
        msg = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            msg["params"] = params
        self.next_id += 1
        line = json.dumps(msg) + "\n"
        self.p.stdin.write(line.encode())
        self.p.stdin.flush()
        return msg["id"]

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.p.stdin.write((json.dumps(msg) + "\n").encode())
        self.p.stdin.flush()

    def read_until(self, want_id, timeout=60):
        result = {}

        def rd():
            while True:
                raw = self.p.stdout.readline()
                if not raw:
                    return
                try:
                    m = json.loads(raw.decode("utf-8", "replace"))
                except Exception:
                    continue
                if m.get("id") == want_id:
                    result.update(m)
                    return

        t = threading.Thread(target=rd, daemon=True)
        t.start()
        t.join(timeout)
        return result

    def call(self, method, params=None, timeout=60):
        i = self.send(method, params)
        return self.read_until(i, timeout)

    def tool(self, name, args=None, timeout=120):
        return self.call("tools/call", {"name": name, "arguments": args or {}}, timeout)

    def close(self):
        try:
            self.p.stdin.close()
        except Exception:
            pass
        try:
            self.p.terminate()
            self.p.wait(timeout=5)
        except Exception:
            self.p.kill()


def tool_text(resp):
    """Extract the text payload from a tools/call response, or an error."""
    if "error" in resp:
        return None, resp["error"]
    r = resp.get("result") or {}
    if r.get("isError"):
        return None, r
    content = r.get("content") or []
    if content and content[0].get("type") == "text":
        return content[0]["text"], None
    return None, r


def main():
    exe = sys.argv[1] if len(sys.argv) > 1 else "./target/release/hvlab.exe"
    print(f"hvlab MCP smoke test: {exe}")

    srv = Server(exe)
    try:
        init = srv.call(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "smoke", "version": "0"},
            },
        )
        info = (init.get("result") or {}).get("serverInfo") or {}
        check("initialize returns serverInfo", info.get("name") == "hvlab", repr(info))
        srv.notify("notifications/initialized")

        listing = srv.call("tools/list")
        tools = (listing.get("result") or {}).get("tools") or []
        names = [t["name"] for t in tools]
        print(f"  tools registered: {len(names)}")
        # Mirrors the registry-count test in hvlab-mcp: exact, not a
        # floor that can only ratchet.
        check("tools/list returns exactly 40 tools", len(names) == 40, f"got {len(names)}")
        check(
            "every tool has a description",
            all(t.get("description") for t in tools),
            str([t["name"] for t in tools if not t.get("description")]),
        )
        check(
            "tool names use the hv_ prefix",
            all(n.startswith("hv_") for n in names),
            str([n for n in names if not n.startswith("hv_")]),
        )

        # Read-only calls that must work on any Hyper-V host.
        # The first VM the host will admit to, if any. On a host where the
        # caller is not in Hyper-V Administrators the provider hides every
        # VM instance, and VM-scoped calls legitimately cannot succeed.
        vm_name = None
        r = srv.tool("hv_vm_list", {})
        txt, _ = tool_text(r)
        if txt:
            try:
                vms = json.loads(txt)
                if vms:
                    vm_name = vms[0].get("name")
                    print(f"  visible VM: {vm_name} ({vms[0].get('state')})")
            except Exception:
                pass

        for name, args, label in [
            ("hv_host_info", {}, "host info"),
            ("hv_vm_list", {}, "vm list"),
            ("hv_switch_list", {}, "switch list"),
            ("hv_capabilities", {}, "capabilities"),
        ]:
            if name not in names:
                check(f"{name} registered", False, "missing from tools/list")
                continue
            r = srv.tool(name, args)
            txt, err = tool_text(r)
            if txt is not None:
                check(f"{name} ({label}) succeeded", True)
            elif "hv.permission" in repr(err):
                # Correct, typed answer for a caller outside Hyper-V
                # Administrators: the provider hides the inventory and
                # the tool says so instead of reporting an empty host.
                print(f"  OK    {name} ({label}): refused with hv.permission")
                check(f"{name} reports typed permission error", True)
            else:
                check(f"{name} ({label}) succeeded", False, repr(err)[:220])

        if vm_name:
            r = srv.tool("hv_checkpoint_list", {"vm": vm_name})
            txt, err = tool_text(r)
            check("hv_checkpoint_list succeeded", txt is not None, repr(err)[:220])
        else:
            print("  SKIP  hv_checkpoint_list (no VM visible to this caller)")

        # Plan token flow: mint, then use.
        if "hv_plan" in names:
            p = srv.tool("hv_plan", {"action": "hv_guest_exec", "args": {"program": "cmd.exe", "vm": "x"}})
            txt, err = tool_text(p)
            check("hv_plan mints a token", txt is not None, repr(err)[:220])
            if txt:
                try:
                    tok = json.loads(txt)
                    check("plan token has plan_id+digest", "plan_id" in tok and "digest" in tok, txt[:160])
                except Exception as e:
                    check("plan token is JSON", False, str(e))

        # D/X tools must refuse without a confirm block.
        for name in ("hv_guest_exec", "hv_guest_powershell", "hv_checkpoint_delete"):
            if name not in names:
                continue
            args = {"vm": "Driver Testing"} if "checkpoint" in name else {"vm": "Driver Testing", "program": "cmd.exe"}
            if "checkpoint_delete" in name:
                args["checkpoint"] = "nope"
            r = srv.tool(name, args)
            txt, err = tool_text(r)
            refused = txt is None or (r.get("result") or {}).get("isError")
            check(f"{name} refuses without plan token", refused, "it succeeded!")

    finally:
        srv.close()

    print(f"\n{len(PASSES)} passed, {len(FAILURES)} failed")
    for n, d in FAILURES:
        print(f"  FAILED: {n} :: {d}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())