#!/usr/bin/env python3
"""Exercise native edge bans using disposable, non-routed source addresses.

Adds expiring manual decisions, which CrowdSec forwards to configured alert
channels. The rule name identifies these as homelab-ban-verification tests.
The reserved source addresses have no country name or flag. Verifies actual
HTTPS and SSH before/during/after bans for IPv4 and IPv6. --http-bouncer adds
brief HTTPS-only exceptions for the disposable IPv4 source in CrowdSec's two
chains to test Traefik independently. Removes every owned exception and link.
This tests edge kernel paths, not upstream router policy or public IPv6 routing.
"""
import argparse
import fcntl
import json
import os
import re
import signal
import subprocess
import time
import uuid
from pathlib import Path


def run(args, check=True, timeout=20):
    p = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f"{args[0]} {args[1:3]}: {p.stderr[-600:]}")
    return p


def set_contains(document, address):
    """Ignore matching rule text and counters when checking decision removal."""

    def contains(value):
        if isinstance(value, str):
            return value == address
        if isinstance(value, list):
            return any(contains(item) for item in value)
        if isinstance(value, dict):
            return any(contains(value[key]) for key in ("elem", "val") if key in value)
        return False

    return any(
        contains(item.get("set", {}).get("elem", [])) for item in document["nftables"]
    )


def owned_exception(document, handle, tag):
    for item in document["nftables"]:
        rule = item.get("rule", {})
        if str(rule.get("handle")) == str(handle):
            if rule.get("comment") != tag:
                raise RuntimeError(
                    "temporary rule ownership changed; refusing deletion"
                )
            return rule
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--edge", choices=["home", "vps"], required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--http-bouncer", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)*", args.hostname):
        raise ValueError("invalid hostname")
    if os.geteuid() != 0:
        raise ValueError("run as root on the selected edge")
    lock = os.open(
        "/run/homelab-crowdsec-probe.lock",
        os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
        0o600,
    )
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    vps = args.edge == "vps"
    if vps != Path("/opt/pangolin").exists():
        raise ValueError("selected edge does not match host")
    if args.http_bouncer and not vps:
        raise ValueError("HTTP bouncer test applies only to VPS")
    tag = "hla" + uuid.uuid4().hex[:6]
    peer = tag + "p"
    cs = ["docker", "exec", "crowdsec", "cscli"] if vps else ["cscli"]
    source4 = "198.18.255.2"
    target4 = "198.18.255.1"
    source6 = "2001:db8:ffff:214::2"
    target6 = "2001:db8:ffff:214::1"
    hostname = args.hostname
    path = "/_matrix/client/versions" if vps else "/health"
    for addr in [source4, source6]:
        existing = json.loads(
            run(cs + ["decisions", "list", "--ip", addr, "-o", "json"]).stdout
        )
        if existing:
            raise RuntimeError("test address already has a decision")
    routes = run(["ip", "-j", "route", "show", "table", "all"]).stdout
    routes += run(["ip", "-6", "-j", "route", "show", "table", "all"]).stdout
    if "198.18.255." in routes or "2001:db8:ffff:214:" in routes:
        raise RuntimeError("test range in use")
    ns = subprocess.Popen(["unshare", "--net", "--", "sleep", "600"])
    results = {
        "edge": "vps" if vps else "home",
        "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "failed",
        "checks": {},
        "test_addresses": [source4, source6],
    }
    added = []
    exceptions = []
    link_created = False

    def remove_exception(chain, handle):
        p = run(["nft", "-j", "list", "chain", "ip", "crowdsec", chain], check=False)
        if p.returncode:
            raise RuntimeError("cannot verify temporary rule ownership")
        rule = owned_exception(json.loads(p.stdout), handle, tag)
        if rule is not None:
            run(["nft", "delete", "rule", "ip", "crowdsec", chain, "handle", handle])

    def nsrun(args, **kw):
        return run(["nsenter", "-t", str(ns.pid), "-n", "--", *args], **kw)

    def curl(addr, extra=None):
        dest = "[" + addr + "]" if ":" in addr else addr
        p = nsrun(
            [
                "curl",
                "--noproxy",
                "*",
                "--silent",
                "--show-error",
                "--max-time",
                "3",
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
                "--resolve",
                f"{hostname}:443:{dest}",
                *(extra or []),
                f"https://{hostname}{path}",
            ],
            check=False,
            timeout=6,
        )
        return {"exit": p.returncode, "http": p.stdout, "error": p.stderr[:150]}

    def ssh_probe(addr):
        code = "import socket,sys; s=socket.create_connection((sys.argv[1],22),2); print(s.recv(150).decode().split()[0])"
        p = nsrun(["python3", "-c", code, addr], check=False, timeout=5)
        return {"exit": p.returncode, "banner": p.stdout.strip()}

    def sets_have(addr):
        family, table = ("ip6", "crowdsec6") if ":" in addr else ("ip", "crowdsec")
        data = json.loads(run(["nft", "-j", "list", "table", family, table]).stdout)
        return set_contains(data, addr)

    def await_set(addr, want):
        for i in range(35):
            if sets_have(addr) == want:
                return
            time.sleep(1)
        raise RuntimeError(f"decision propagation failed {addr} expected{want}")

    def delete(addr):
        # Only this exact, previously absent fixture address is changed; bans expire independently.
        run(cs + ["decisions", "delete", "--ip", addr])
        added.remove(addr)
        await_set(addr, False)

    try:
        for i in range(30):
            if os.readlink(f"/proc/{ns.pid}/ns/net") != os.readlink(
                "/proc/self/ns/net"
            ):
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("namespace isolation absent")
        run(["ip", "link", "add", tag, "type", "veth", "peer", "name", peer])
        link_created = True
        run(["ip", "link", "set", peer, "netns", str(ns.pid)])
        run(["ip", "addr", "add", target4 + "/30", "dev", tag])
        run(["ip", "-6", "addr", "add", target6 + "/64", "dev", tag, "nodad"])
        run(["ip", "link", "set", tag, "up"])
        nsrun(["ip", "link", "set", "lo", "up"])
        nsrun(["ip", "addr", "add", source4 + "/30", "dev", peer])
        nsrun(["ip", "-6", "addr", "add", source6 + "/64", "dev", peer, "nodad"])
        nsrun(["ip", "link", "set", peer, "up"])
        nsrun(["ip", "route", "add", "default", "via", target4])
        nsrun(["ip", "-6", "route", "add", "default", "via", target6])
        for family, src, dst in [
            ("ipv4", source4, target4),
            ("ipv6", source6, target6),
        ]:
            check = {"before": curl(dst), "ssh_before": ssh_probe(dst)}
            results["checks"][family] = check
            if check["before"]["http"] != "200" or check["ssh_before"]["exit"] != 0:
                raise RuntimeError("baseline not reachable")
            check["forged_headers_before"] = curl(
                dst, ["-H", "X-Forwarded-For: 127.0.0.1", "-H", "X-Real-IP: 127.0.0.1"]
            )
            start = time.monotonic()
            run(
                cs
                + [
                    "decisions",
                    "add",
                    "--ip",
                    src,
                    "--duration",
                    "3m",
                    "--reason",
                    "homelab-ban-verification-" + tag,
                ]
            )
            added.append(src)
            await_set(src, True)
            check["propagation_seconds"] = round(time.monotonic() - start, 2)
            check["banned"] = curl(dst)
            check["ssh_banned"] = ssh_probe(dst)
            check["forged_headers_banned"] = curl(
                dst, ["-H", "X-Forwarded-For: 127.0.0.1", "-H", "X-Real-IP: 127.0.0.1"]
            )
            if (
                check["banned"]["exit"] != 28
                or check["ssh_banned"]["exit"] == 0
                or check["forged_headers_banned"]["exit"] != 28
            ):
                raise RuntimeError("ban bypassed")
            if args.http_bouncer and family == "ipv4":
                # Exempt only the disposable source's HTTPS packets from these two chains.
                # This isolates the real Traefik bouncer without opening access for any user.
                for chain in ["crowdsec-chain-input", "crowdsec-chain-forward"]:
                    run(
                        [
                            "nft",
                            "insert",
                            "rule",
                            "ip",
                            "crowdsec",
                            chain,
                            "ip",
                            "saddr",
                            src,
                            "tcp",
                            "dport",
                            "443",
                            "counter",
                            "return",
                            "comment",
                            tag,
                        ]
                    )
                    rules = json.loads(
                        run(
                            ["nft", "-j", "list", "chain", "ip", "crowdsec", chain]
                        ).stdout
                    )["nftables"]
                    handle = next(
                        o["rule"]["handle"]
                        for o in rules
                        if o.get("rule", {}).get("comment") == tag
                    )
                    exceptions.append((chain, str(handle)))
                for attempt in range(40):
                    check["http_bouncer_only"] = curl(dst)
                    if check["http_bouncer_only"]["http"] == "403":
                        break
                    time.sleep(2)
                else:
                    raise RuntimeError(
                        "Traefik did not enforce the decision independently"
                    )
                check["http_bouncer_forged_headers"] = curl(
                    dst,
                    ["-H", "X-Forwarded-For: 127.0.0.1", "-H", "X-Real-IP: 127.0.0.1"],
                )
                if check["http_bouncer_forged_headers"]["http"] != "403":
                    raise RuntimeError("Traefik header spoof bypassed decision")
            delete(src)
            for attempt in range(40):
                check["after"] = curl(dst)
                if check["after"]["http"] == "200":
                    break
                time.sleep(2)
            for chain, handle in exceptions:
                rules = json.loads(
                    run(["nft", "-j", "list", "chain", "ip", "crowdsec", chain]).stdout
                )["nftables"]
                owned = next(
                    o["rule"] for o in rules if o.get("rule", {}).get("comment") == tag
                )
                check.setdefault("http_bouncer_kernel_paths", {})[chain] = sum(
                    expression.get("counter", {}).get("packets", 0)
                    for expression in owned["expr"]
                    if isinstance(expression.get("counter"), dict)
                )
                remove_exception(chain, handle)
            exceptions.clear()
            check["ssh_after"] = ssh_probe(dst)
            if check["after"]["http"] != "200" or check["ssh_after"]["exit"] != 0:
                raise RuntimeError("recovery failed")
        results["status"] = "passed"
    except Exception as e:
        results["error"] = str(e)
    finally:
        for chain, handle in exceptions:
            try:
                remove_exception(chain, handle)
            except Exception as e:
                results.setdefault("cleanup_errors", []).append(str(e))
        for addr in list(added):
            try:
                delete(addr)
            except Exception as e:
                results.setdefault("cleanup_errors", []).append(str(e))
        if link_created:
            run(["ip", "link", "delete", tag], check=False)
        ns.terminate()
        ns.wait(timeout=5)
        results["namespace_removed"] = not Path(f"/proc/{ns.pid}").exists()
        results["link_removed"] = (
            run(["ip", "link", "show", tag], check=False).returncode != 0
        )
        if not results["namespace_removed"] or not results["link_removed"]:
            results.setdefault("cleanup_errors", []).append("fixture resource remains")
        os.close(lock)
        print(json.dumps(results, indent=2), flush=True)
    if results["status"] != "passed" or results.get("cleanup_errors"):
        raise SystemExit(1)


if __name__ == "__main__":
    signal.signal(
        signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError("test deadline"))
    )
    signal.alarm(300)
    main()
