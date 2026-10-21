#!/usr/bin/env python3
"""Test the installed bouncer in a private network namespace with a fixture API.

Uses native nftables and the installed binary/configuration. Only the fixture
API endpoint, key, polling and logging differ. Tests cold startup, API outage,
and restart after emptying the isolated ruleset. Does not restart live services.
"""
import http.server, json, os, signal, socket, subprocess, tempfile, threading, time
from pathlib import Path


def run(args, check=True):
    p = subprocess.run(args, capture_output=True, text=True, timeout=15)
    if check and p.returncode:
        raise RuntimeError(p.stderr[-400:])
    return p


def fixture(parent):
    if os.readlink("/proc/self/ns/net") == parent:
        raise RuntimeError("network isolation failed")
    run(["ip", "link", "set", "lo", "up"])
    for family, addr in [("-4", "198.18.255.2/32"), ("-6", "2001:db8:ffff:214::2/128")]:
        run(["ip", family, "addr", "add", addr, "dev", "lo"])
    state = {"outage": False, "startup_requests": 0, "outage_requests": 0}

    class API(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if state["outage"]:
                state["outage_requests"] += 1
                self.send_response(503)
                self.end_headers()
                return
            new = []
            if "startup=true" in self.path:
                state["startup_requests"] += 1
                new = [
                    {
                        "id": i + 1,
                        "origin": "cscli",
                        "type": "ban",
                        "scope": "Ip",
                        "value": value,
                        "duration": "120s",
                        "scenario": "isolated-lifecycle-proof",
                    }
                    for i, value in enumerate(["198.18.255.2", "2001:db8:ffff:214::2"])
                ]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"new": new, "deleted": []}).encode())

    api = http.server.ThreadingHTTPServer(("127.0.0.1", 18080), API)
    threading.Thread(target=api.serve_forever, daemon=True).start()
    servers = []
    for af, addr in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
        sock = socket.socket(af)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((addr, 18443))
        sock.listen()
        servers.append(sock)

        def serve(s):
            while True:
                try:
                    c, _ = s.accept()
                    c.close()
                except OSError:
                    return

        threading.Thread(target=serve, args=(sock,), daemon=True).start()

    def connect(af, source, dest):
        s = socket.socket(af)
        s.settimeout(0.7)
        try:
            s.bind((source, 0))
            s.connect((dest, 18443))
            return True
        except TimeoutError:
            return False
        finally:
            s.close()

    def probes():
        return [
            connect(socket.AF_INET, "198.18.255.2", "127.0.0.1"),
            connect(socket.AF_INET6, "2001:db8:ffff:214::2", "::1"),
        ]

    result = {"status": "failed", "private_network": True, "before": probes()}
    assert result["before"] == [True, True]
    with tempfile.TemporaryDirectory(prefix="bouncer-native-fixture-") as tmp:
        path = Path(tmp)
        config = Path(
            "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
        ).read_text()
        import re

        config = re.sub(
            r"^api_url:.*$", "api_url: http://127.0.0.1:18080/", config, flags=re.M
        )
        config = re.sub(
            r"^api_key:.*$", "api_key: isolated-fixture-only", config, flags=re.M
        )
        config = re.sub(
            r"^update_frequency:.*$", "update_frequency: 1s", config, flags=re.M
        )
        config = re.sub(r"^log_mode:.*$", "log_mode: stdout", config, flags=re.M)
        config = re.sub(r"^log_dir:.*$", "log_dir: " + tmp, config, flags=re.M)
        cfg = path / "config.yaml"
        cfg.write_text(config)
        cfg.chmod(0o600)
        log = (path / "log").open("w+")
        process = None

        def start():
            p = subprocess.Popen(
                ["/usr/bin/crowdsec-firewall-bouncer", "-c", str(cfg)],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            for _ in range(35):
                if p.poll() is not None:
                    raise RuntimeError("native bouncer exited during startup")
                if probes() == [False, False]:
                    return p
                time.sleep(0.3)
            p.terminate()
            p.wait()
            raise RuntimeError("cold-start decisions were not enforced")

        def stop(p):
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()

        try:
            process = start()
            result["cold_start_both_families_blocked"] = True
            state["outage"] = True
            for _ in range(20):
                if state["outage_requests"]:
                    break
                time.sleep(0.5)
            time.sleep(5)
            result["api_unavailable_requests"] = state["outage_requests"]
            result["api_outage_process_alive"] = process.poll() is None
            result["api_outage_both_families_blocked"] = probes() == [False, False]
            if (
                not result["api_unavailable_requests"]
                or not result["api_outage_both_families_blocked"]
            ):
                raise RuntimeError("API outage lost enforcement")
            state["outage"] = False
            stop(process)
            process = None
            run(["nft", "flush", "ruleset"])
            assert probes() == [True, True]
            process = start()
            result["restart_from_empty_ruleset_blocked"] = True
            result["startup_full_refreshes"] = state["startup_requests"]
            if result["startup_full_refreshes"] < 2:
                raise RuntimeError("restart reused no verified full refresh")
            result["status"] = "passed"
        except Exception as e:
            result["error"] = str(e)
            log.flush()
            log.seek(0)
            result["diagnostics"] = log.read()[-2000:]
        finally:
            if process is not None:
                stop(process)
            log.close()
            api.shutdown()
            for s in servers:
                s.close()
    return result


def main():
    if os.geteuid() != 0:
        raise ValueError("run as root on an edge host")
    parent = os.readlink("/proc/self/ns/net")
    identity = [
        "systemctl",
        "show",
        "crowdsec-firewall-bouncer.service",
        "--property=MainPID,ActiveState,ActiveEnterTimestampMonotonic",
    ]
    before = run(identity).stdout
    import inspect

    code = "import http.server,json,os,signal,socket,subprocess,tempfile,threading,time\nfrom pathlib import Path\n"
    code += (
        inspect.getsource(run)
        + "\n"
        + inspect.getsource(fixture)
        + f"\nprint(json.dumps(fixture({parent!r})))\n"
    )
    process = subprocess.Popen(
        ["unshare", "--net", "--", "python3", "-"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        out, err = process.communicate(code, timeout=150)
    except BaseException:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        raise
    if process.returncode:
        raise RuntimeError(err[-1000:])
    result = json.loads(out)
    result["production_service_unchanged"] = run(identity).stdout == before
    print(json.dumps(result, indent=2))
    if result["status"] != "passed" or not result["production_service_unchanged"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
