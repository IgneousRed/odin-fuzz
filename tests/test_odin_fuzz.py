"""Behavior-level verification fixtures for odin-fuzz."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = [os.environ["ODIN_FUZZ_BIN"]] if os.environ.get("ODIN_FUZZ_BIN") else [sys.executable, str(ROOT / "odin-fuzz")]


def run_cli(*args, cwd=ROOT):
    return subprocess.run(
        [*CLI, *(str(a) for a in args)],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=180,
    )


def write_files(base, mapping):
    for rel, content in mapping.items():
        path = Path(base) / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def latest_report(work_dir):
    latest = json.loads((Path(work_dir) / "latest.json").read_text(encoding="utf-8"))
    run_dir = Path(latest["run_directory"])
    return run_dir, json.loads((run_dir / "report.json").read_text(encoding="utf-8"))


class OdinFuzzBehaviorTests(unittest.TestCase):
    def test_doctor_and_scan_inventory_with_build_tags(self):
        doc = run_cli("doctor")
        self.assertEqual(doc.returncode, 0, doc.stderr)
        info = json.loads(doc.stdout)
        self.assertTrue(Path(info["odin"]).is_file())

        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            write_files(proj, {
                "src/main.odin": '''package app
import "core:os"
import "core:time"
main :: proc() {
	_ = os.args
	_, _ = os.lookup_env("APP_MODE", context.allocator)
	_ = time.now()
}
''',
                "src/main_web.odin": '''#+build js
package app
import rl "vendor:raylib"
main :: proc() {
	_ = rl.WindowShouldClose()
}
''',
            })
            scan = run_cli("scan", proj, "--work-dir", work)
            self.assertEqual(scan.returncode, 0, scan.stderr)
            data = json.loads(scan.stdout)
            by_path = {s["path"]: s for s in data["sources"]}
            self.assertTrue(by_path["src/main.odin"]["darwin_active"])
            self.assertFalse(by_path["src/main_web.odin"]["darwin_active"])
            self.assertEqual(len(data["applications"]), 1)
            inv = {i["kind"]: i["status"] for i in data["applications"][0]["inventory"]}
            self.assertEqual(inv["argv"], "driven")
            self.assertEqual(inv["environment"], "driven")
            self.assertEqual(inv["clock"], "nondeterministic_gap")
            self.assertNotIn("ui", inv)

    def test_confirmed_assertion_replay_and_tamper_rejection(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            write_files(proj, {
                "src/main.odin": '''package app
import "core:os"
main :: proc() {
	if len(os.args) < 2 {
		os.exit(1)
	}
	if os.args[1] == "--boom" {
		assert(false, "triggered via cli")
	}
}
''',
            })
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "15", "--max-cases", "80", "--seed", "1")
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            _, report = latest_report(work)
            findings = report["applications"][0]["findings"]
            self.assertEqual(len(findings), 1)
            finding = findings[0]
            self.assertEqual(finding["kind"], "runtime assertion")
            self.assertIn("src/main.odin(", finding["site"])

            fdir = Path(finding["directory"])
            rep = run_cli("reproduce", fdir)
            self.assertEqual(rep.returncode, 1, rep.stdout + rep.stderr)
            self.assertIn("Confirmed failure reproduced.", rep.stdout)

            # Tampering with case.json must cause replay to refuse.
            case_path = fdir / "case.json"
            case_path.write_text(case_path.read_text() + " ", encoding="utf-8")
            tampered = run_cli("reproduce", fdir)
            self.assertEqual(tampered.returncode, 2, tampered.stdout + tampered.stderr)
            self.assertIn("refusing replay", tampered.stderr)

    def test_confirmed_asan_uaf_and_bounds_check(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            write_files(proj, {
                "src/main.odin": '''package app
import "core:fmt"
import "core:os"
main :: proc() {
	if len(os.args) < 2 { return }
	data, err := os.read_entire_file(os.args[1], context.allocator)
	if err != nil { os.exit(1) }
	defer delete(data)
	text := string(data)
	if text == "trigger_uaf" {
		p := new(int)
		free(p)
		p^ = 123
		fmt.println(p^)
	} else if text == "trigger_bounds" {
		arr := [2]int{1, 2}
		idx := len(data)
		fmt.println(arr[idx])
	}
}
''',
                "odin-fuzz.json": json.dumps({
                    "applications": [{"path": "src", "args": ["{file}"], "files": ["input.txt"]}]
                }),
            })
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "20", "--max-cases", "120", "--seed", "1")
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            _, report = latest_report(work)
            findings = report["applications"][0]["findings"]
            kinds = {f["kind"] for f in findings}
            self.assertIn("address_sanitizer", kinds, findings)
            self.assertIn("bounds check failed", kinds, findings)
            for finding in findings:
                rep = run_cli("reproduce", finding["directory"])
                self.assertEqual(rep.returncode, 1, rep.stdout + rep.stderr)

    def test_counterexample_unreachable_internal_and_ordinary_rejection(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            write_files(proj, {
                "src/main.odin": '''package app
import "core:fmt"
import "core:os"

// Unreachable from main: direct-call fuzzing would falsely report this,
// while interface-reachable application fuzzing must NOT report it.
internal_only_crash :: proc(x: int) {
	if x != 0 {
		assert(false, "unreachable internal failure")
	}
}

main :: proc() {
	_ = internal_only_crash
	if len(os.args) > 1 && os.args[1] == "--ok" {
		fmt.println("ok")
		return
	}
	fmt.eprintln("usage: app --ok")
	os.exit(1)
}
''',
            })
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "8", "--max-cases", "25", "--seed", "1")
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            _, report = latest_report(work)
            app_res = report["applications"][0]
            self.assertEqual(app_res["status"], "explored")
            self.assertEqual(app_res["findings"], [])
            self.assertGreater(app_res["ordinary_or_unclassified_exits"], 0)

    def test_multi_step_stateful_restart_sequence(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            write_files(proj, {
                "src/main.odin": '''package app
import "core:os"
main :: proc() {
	if len(os.args) < 2 {
		_ = os.write_entire_file("session.state", transmute([]u8)string("ready"))
		return
	}
	if os.args[1] == "--init" {
		_ = os.write_entire_file("session.state", transmute([]u8)string("ready"))
		return
	}
	if os.args[1] == "--commit" {
		data, err := os.read_entire_file("session.state", context.allocator)
		if err != nil { os.exit(1) }
		defer delete(data)
		if string(data) == "ready" {
			assert(false, "stateful two-step bug")
		}
	}
	os.exit(1)
}
''',
            })
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "20", "--max-cases", "120", "--seed", "2")
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            _, report = latest_report(work)
            findings = report["applications"][0]["findings"]
            self.assertEqual(len(findings), 1)
            finding = findings[0]
            self.assertGreaterEqual(finding["step_count"], 2)
            self.assertGreaterEqual(finding["failing_step"], 1)
            rep = run_cli("reproduce", finding["directory"])
            self.assertEqual(rep.returncode, 1, rep.stdout + rep.stderr)

    def test_ui_events_adapter_and_unsupported_ui_gap(self):
        # 1. App with a replayable ui_events boundary adapter
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            write_files(proj, {
                "src/main.odin": '''package app
import "core:encoding/json"
import "core:os"

Frame_Event :: struct {
	frame:        int,
	keys_pressed: []string,
	close:        bool,
}

main :: proc() {
	if len(os.args) < 2 { os.exit(1) }
	data, err := os.read_entire_file(os.args[1], context.allocator)
	if err != nil { os.exit(1) }
	defer delete(data)
	events: []Frame_Event
	if json.unmarshal(data, &events) != nil { os.exit(1) }
	armed := false
	for ev in events {
		for k in ev.keys_pressed {
			if k == "SPACE" {
				if armed {
					assert(false, "double-space frame transition bug")
				}
				armed = true
			}
		}
		if ev.close { break }
	}
}
''',
                "odin-fuzz.json": json.dumps({
                    "applications": [{
                        "path": "src",
                        "name": "frame-ui",
                        "args": ["{events}"],
                        "ui_events": {"mode": "file", "path": "events.json", "keys": ["SPACE", "ESCAPE"], "max_frames": 8},
                    }]
                }),
            })
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "15", "--max-cases", "60", "--seed", "1")
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            _, report = latest_report(work)
            findings = report["applications"][0]["findings"]
            self.assertEqual(len(findings), 1)
            inv = {i["kind"]: i["status"] for i in report["applications"][0]["inventory"]}
            self.assertEqual(inv["ui"], "adapter_driven")
            rep = run_cli("reproduce", findings[0]["directory"])
            self.assertEqual(rep.returncode, 1, rep.stdout + rep.stderr)

        # 2. Raylib UI app WITHOUT ui_events adapter must NOT launch and must report unsupported gap
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            write_files(proj, {
                "src/main.odin": '''package app
import rl "vendor:raylib"
main :: proc() {
	_ = rl.WindowShouldClose()
}
''',
            })
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "5", "--max-cases", "5")
            self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
            _, report = latest_report(work)
            self.assertEqual(report["applications"][0]["status"], "unsupported")
            self.assertTrue(any("ui input is inventoried" in g for g in report["gaps"]))

    def test_local_network_and_local_ipc_disposable_drivers(self):
        # 1. Local loopback TCP network driver
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            write_files(proj, {
                "src/main.odin": '''package app
import "core:net"
import "core:os"
import "core:strconv"
main :: proc() {
	port_str, ok := os.lookup_env("APP_PORT", context.allocator)
	if !ok { os.exit(1) }
	port, parsed := strconv.parse_int(port_str)
	if !parsed { os.exit(1) }
	sock, err := net.dial_tcp(net.Endpoint{address = net.IP4_Loopback, port = port})
	if err != nil { os.exit(1) }
	defer net.close(sock)
	buf: [256]u8
	n, rerr := net.recv_tcp(sock, buf[:])
	if rerr != nil { os.exit(1) }
	if string(buf[:n]) == "NET_CRASH" {
		assert(false, "network payload bug")
	}
}
''',
                "odin-fuzz.json": json.dumps({
                    "applications": [{
                        "path": "src",
                        "name": "net-client",
                        "local_network": {"role": "server", "port_env": "APP_PORT"},
                    }]
                }),
            })
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "15", "--max-cases", "80", "--seed", "1")
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            _, report = latest_report(work)
            findings = report["applications"][0]["findings"]
            self.assertEqual(len(findings), 1)
            rep = run_cli("reproduce", findings[0]["directory"])
            self.assertEqual(rep.returncode, 1, rep.stdout + rep.stderr)

        # 2. Local Unix domain socket IPC driver
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            write_files(proj, {
                "src/main.odin": '''package app
import "core:os"
import "core:sys/posix"
main :: proc() {
	sock_path, ok := os.lookup_env("APP_SOCK", context.allocator)
	if !ok { os.exit(1) }
	fd := posix.socket(.UNIX, .STREAM, nil)
	if fd < 0 { os.exit(1) }
	defer posix.close(fd)
	addr: posix.sockaddr_un
	addr.sun_family = .UNIX
	for i := 0; i < len(sock_path) && i < len(addr.sun_path) - 1; i += 1 {
		addr.sun_path[i] = sock_path[i]
	}
	if posix.connect(fd, cast(^posix.sockaddr)&addr, size_of(posix.sockaddr_un)) != .OK {
		os.exit(1)
	}
	buf: [256]u8
	n := posix.read(fd, raw_data(buf[:]), len(buf))
	if n > 0 && string(buf[:n]) == "IPC_CRASH" {
		assert(false, "ipc payload bug")
	}
}
''',
                "odin-fuzz.json": json.dumps({
                    "applications": [{
                        "path": "src",
                        "name": "ipc-client",
                        "local_ipc": {"role": "server", "socket_env": "APP_SOCK"},
                    }]
                }),
            })
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "15", "--max-cases", "80", "--seed", "1")
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            _, report = latest_report(work)
            findings = report["applications"][0]["findings"]
            self.assertEqual(len(findings), 1)
            rep = run_cli("reproduce", findings[0]["directory"])
            self.assertEqual(rep.returncode, 1, rep.stdout + rep.stderr)

    def test_deterministic_seed_and_clock_and_sandbox_isolation(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            outside_secret = Path(td) / "outside_secret.txt"
            outside_secret.write_text("TOP_SECRET", encoding="utf-8")
            outside_write = Path(td) / "outside_write.txt"
            write_files(proj, {
                "src/main.odin": f'''package app
import "core:os"
import "core:strconv"
main :: proc() {{
	// Verify sandbox blocks external reads and writes.
	if data, err := os.read_entire_file({json.dumps(str(outside_secret))}, context.allocator); err == nil {{
		delete(data)
		panic("sandbox read escape")
	}}
	if os.write_entire_file({json.dumps(str(outside_write))}, transmute([]u8)string("escaped")) == nil {{
		panic("sandbox write escape")
	}}
	seed_str, ok := os.lookup_env("APP_SEED", context.allocator)
	if !ok {{ os.exit(1) }}
	seed, parsed := strconv.parse_int(seed_str)
	if !parsed {{ os.exit(1) }}
	if seed == 42 {{
		assert(false, "seed 42 bug")
	}}
}}
''',
                "odin-fuzz.json": json.dumps({
                    "applications": [{
                        "path": "src",
                        "seed_env": "APP_SEED",
                        "clock_env": "APP_TIME",
                    }]
                }),
            })
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "15", "--max-cases", "20", "--seed", "1")
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            self.assertFalse(outside_write.exists())
            _, report = latest_report(work)
            findings = report["applications"][0]["findings"]
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["kind"], "runtime assertion")
            rep = run_cli("reproduce", findings[0]["directory"])
            self.assertEqual(rep.returncode, 1, rep.stdout + rep.stderr)

    def test_config_validation_rejects_invalid_settings(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            write_files(proj, {
                "src/main.odin": "package app\nmain :: proc() {}\n",
                "odin-fuzz.json": json.dumps({"unknown_key": 1}),
            })
            res = run_cli("scan", proj, "--work-dir", work)
            self.assertEqual(res.returncode, 2)

            write_files(proj, {
                "odin-fuzz.json": json.dumps({"applications": [{"path": "src", "seed_env": "ASAN_OPTIONS"}]}),
            })
            res2 = run_cli("scan", proj, "--work-dir", work)
            self.assertEqual(res2.returncode, 2)

            # Orphan placeholders without corresponding adapter blocks must be rejected (Finding 11).
            for args_list in (["{events}"], ["{port}"], ["{socket}"]):
                write_files(proj, {
                    "odin-fuzz.json": json.dumps({"applications": [{"path": "src", "args": args_list}]}),
                })
                bad = run_cli("scan", proj, "--work-dir", work)
                self.assertEqual(bad.returncode, 2, f"expected rejection for {args_list}")

            # Non-object ols.json must fail cleanly with exit 2.
            write_files(proj, {"odin-fuzz.json": "{}", "ols.json": "[]"})
            bad_ols = run_cli("scan", proj, "--work-dir", work)
            self.assertEqual(bad_ols.returncode, 2)

    def test_step_symlink_escape_and_hostile_workspace_nodes(self):
        sys.path.insert(0, str(ROOT / "tools"))
        import odin_fuzz

        with tempfile.TemporaryDirectory() as td:
            td = Path(td).resolve()
            outside_dir = td / "outside_dir"
            outside_dir.mkdir()
            outside_keep = outside_dir / "keep.txt"
            outside_keep.write_text("KEEP", encoding="utf-8")
            outside_target = td / "outside_target.txt"
            outside_target.write_text("ORIG_TARGET", encoding="utf-8")
            outside_events = td / "outside_events.txt"
            outside_events.write_text("ORIG_EVENTS", encoding="utf-8")

            proj = td / "proj"
            work = td / "work"
            write_files(proj, {
                "src/main.odin": f'''package app
import "core:os"
import "core:sys/posix"
main :: proc() {{
	if len(os.args) > 1 && os.args[1] == "step0" {{
		_ = posix.symlink({json.dumps(str(outside_target))}, "input.json")
		_ = posix.symlink({json.dumps(str(outside_dir))}, "sub")
		_ = posix.symlink({json.dumps(str(outside_events))}, "events.json")
		_ = posix.mkdir("collide.txt", {{.IRUSR, .IWUSR, .IXUSR}})
		_ = posix.mkfifo("fifo_node", {{.IRUSR, .IWUSR}})
		_ = posix.mkdir("ro_dir", {{.IRUSR, .IWUSR, .IXUSR}})
		_ = os.write_entire_file("ro_dir/inner", transmute([]u8)string("x"))
		_ = posix.chmod("ro_dir/inner", {{}})
		_ = posix.chmod("ro_dir", {{}})
	}}
}}
''',
            })
            # Build once through odin_fuzz helpers and run a 2-step sequence directly.
            chain = odin_fuzz.toolchain()
            initial = work / "initial"
            odin_fuzz.snapshot_tree(proj, initial)
            odin_fuzz.build_application({"path": "src"}, initial, chain, odin_fuzz.project_settings(proj), work)
            env = {**odin_fuzz.BASE_ENV, "ASAN_OPTIONS": odin_fuzz.ASAN_OPTIONS}
            case = {
                "steps": [
                    {"argv": ["step0"], "stdin": "", "files": {}, "environment": {}},
                    {
                        "argv": ["step1"],
                        "stdin": "",
                        "files": {
                            "input.json": odin_fuzz.encode(b"STEP1_INPUT"),
                            "sub/pwn.txt": odin_fuzz.encode(b"STEP1_SUB"),
                            "collide.txt": odin_fuzz.encode(b"STEP1_COLLIDE"),
                            "fifo_node": odin_fuzz.encode(b"STEP1_FIFO"),
                        },
                        "delete_files": ["sub/keep.txt"],
                        "environment": {},
                        "ui_events": [{"frame": 0, "close": True}],
                    },
                ]
            }
            app_cfg = {"ui_events": {"mode": "file", "path": "events.json"}}
            res = odin_fuzz.execute_case(initial, case, work / "scratch", env, 5.0, app_cfg)
            self.assertEqual(res["returncode"], 0)
            self.assertEqual(outside_target.read_text(encoding="utf-8"), "ORIG_TARGET")
            self.assertEqual(outside_events.read_text(encoding="utf-8"), "ORIG_EVENTS")
            self.assertEqual(outside_keep.read_text(encoding="utf-8"), "KEEP")
            self.assertFalse((outside_dir / "pwn.txt").exists())
            self.assertEqual((work / "scratch" / "workspace" / "fifo_node").read_bytes(), b"STEP1_FIFO")
            # safe_rmtree must clean read-only ro_dir cleanly without raising.
            odin_fuzz.safe_rmtree(work / "scratch")
            self.assertFalse((work / "scratch").exists())

            # Hostile coverage symlink/FIFO, absolute workspace paths, and max_frames=1 UI edge cases.
            cov_link = td / "cov_link.bin"
            os.symlink(outside_target, cov_link)
            self.assertEqual(odin_fuzz.read_coverage(cov_link, [], [])["edges"], set())
            with self.assertRaises(odin_fuzz.WorkspaceError):
                odin_fuzz.safe_workspace_write(td, "/etc/hosts", b"nope")
            with self.assertRaises(odin_fuzz.WorkspaceError):
                odin_fuzz.safe_workspace_write(td, "sub/.hidden", b"nope")
            rng = __import__("random").Random(1)
            ev1 = odin_fuzz.generate_ui_events(rng, {"max_frames": 1, "keys": ["A"]}, 5)
            self.assertEqual(len(ev1), 1)
            ev2 = odin_fuzz._append_ui_frame(ev1, "A", 1)
            self.assertEqual(len(ev2), 1)

    def test_short_path_ipc_and_unicode_sandbox(self):
        # 1. Short path (<96 UTF-8 bytes) local_ipc server + client roles (Finding 2).
        short_base = Path(tempfile.mkdtemp(prefix="ofz_ipc_", dir="/tmp"))
        try:
            proj = short_base / "p"
            work = short_base / "w"
            write_files(proj, {
                "src/main.odin": '''package app
import "core:os"
import "core:sys/posix"
main :: proc() {
	sock_path, ok := os.lookup_env("S", context.allocator)
	if !ok { os.exit(1) }
	fd := posix.socket(.UNIX, .STREAM, nil)
	if fd < 0 { os.exit(1) }
	defer posix.close(fd)
	addr: posix.sockaddr_un
	addr.sun_family = .UNIX
	for i := 0; i < len(sock_path) && i < len(addr.sun_path) - 1; i += 1 {
		addr.sun_path[i] = sock_path[i]
	}
	if posix.connect(fd, cast(^posix.sockaddr)&addr, size_of(posix.sockaddr_un)) != .OK {
		os.exit(1)
	}
	buf: [64]u8
	n := posix.read(fd, raw_data(buf[:]), len(buf))
	if n > 0 && string(buf[:n]) == "SHORT_IPC_BOOM" {
		assert(false, "short path ipc boom")
	}
}
''',
                "odin-fuzz.json": json.dumps({
                    "applications": [{"path": "src", "local_ipc": {"role": "server", "socket_env": "S"}}]
                }),
            })
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "15", "--max-cases", "60", "--seed", "1")
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            _, report = latest_report(work)
            finding = report["applications"][0]["findings"][0]
            rep = run_cli("reproduce", finding["directory"])
            self.assertEqual(rep.returncode, 1, rep.stdout + rep.stderr)

            # 1b. Short path local_ipc role="client" (app binds/listens on short socket, odin-fuzz connects).
            proj_c = short_base / "pc"
            work_c = short_base / "wc"
            write_files(proj_c, {
                "src/main.odin": '''package app
import "core:os"
import "core:sys/posix"
main :: proc() {
	sock_path, ok := os.lookup_env("S", context.allocator)
	if !ok { os.exit(1) }
	fd := posix.socket(.UNIX, .STREAM, nil)
	if fd < 0 { os.exit(1) }
	defer posix.close(fd)
	addr: posix.sockaddr_un
	addr.sun_family = .UNIX
	for i := 0; i < len(sock_path) && i < len(addr.sun_path) - 1; i += 1 {
		addr.sun_path[i] = sock_path[i]
	}
	if posix.bind(fd, cast(^posix.sockaddr)&addr, size_of(posix.sockaddr_un)) != .OK { os.exit(1) }
	if posix.listen(fd, 1) != .OK { os.exit(1) }
	client := posix.accept(fd, nil, nil)
	if client < 0 { os.exit(1) }
	defer posix.close(client)
	buf: [64]u8
	n := posix.read(client, raw_data(buf[:]), len(buf))
	if n > 0 && string(buf[:n]) == "CLIENT_IPC_BOOM" {
		assert(false, "short path ipc client-role boom")
	}
}
''',
                "odin-fuzz.json": json.dumps({
                    "applications": [{"path": "src", "local_ipc": {"role": "client", "socket_env": "S"}}]
                }),
            })
            res_c = run_cli("explore", proj_c, "--work-dir", work_c, "--budget", "15", "--max-cases", "60", "--seed", "1")
            self.assertEqual(res_c.returncode, 1, res_c.stdout + res_c.stderr)
            _, report_c = latest_report(work_c)
            rep_c = run_cli("reproduce", report_c["applications"][0]["findings"][0]["directory"])
            self.assertEqual(rep_c.returncode, 1, rep_c.stdout + rep_c.stderr)
        finally:
            import shutil
            shutil.rmtree(short_base, ignore_errors=True)

        # 2. Unicode path ("café") under macOS Seatbelt sandbox (Finding 6).
        with tempfile.TemporaryDirectory(prefix="ofz_café_") as td:
            proj = Path(td) / "café_app"
            work = Path(td) / "café_work"
            write_files(proj, {
                "data.txt": "CAFE_OK",
                "src/main.odin": '''package app
import "core:os"
main :: proc() {
	data, err := os.read_entire_file("data.txt", context.allocator)
	if err != nil { os.exit(1) }
	defer delete(data)
	if string(data) == "CAFE_OK" {
		assert(false, "unicode path readable inside sandbox")
	}
}
''',
            })
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "10", "--max-cases", "5", "--seed", "1")
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            _, report = latest_report(work)
            rep = run_cli("reproduce", report["applications"][0]["findings"][0]["directory"])
            self.assertEqual(rep.returncode, 1, rep.stdout + rep.stderr)

    def test_unsafe_discovered_filenames_and_dir_collision(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            write_files(proj, {
                "src/main.odin": '''package app
import "core:os"
main :: proc() {
	_, _ = os.read_entire_file("/etc/hosts", context.allocator)
	_, _ = os.read_entire_file(".env", context.allocator)
	_, _ = os.read_directory_by_path(".", 0, context.allocator)
	_, _ = os.read_directory_by_path("src", 0, context.allocator)
}
''',
            })
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "8", "--max-cases", "8", "--seed", "1")
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            _, report = latest_report(work)
            self.assertGreater(report["applications"][0]["executions"], 0)

    def test_odin_build_tags_and_ignore_semantics(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            host_arch = "arm64" if os.uname().machine.lower() in {"arm64", "aarch64"} else "amd64"
            other_arch = "amd64" if host_arch == "arm64" else "arm64"
            write_files(proj, {
                "src/base.odin": "package app\nmain :: proc() {}\n",
                "src/t_or_ok.odin": "#+build darwin, linux\npackage app\n",
                "src/t_or_no.odin": "#+build windows, linux\npackage app\n",
                "src/t_and_no.odin": f"#+build windows {host_arch}\npackage app\n",
                "src/t_and_ok.odin": f"#+build darwin {host_arch}\npackage app\n",
                "src/t_arch_no.odin": f"#+build darwin {other_arch}\npackage app\n",
                "src/t_notdarwin.odin": f"#+build !darwin {host_arch}\npackage app\n",
                "src/t_or_arch.odin": f"#+build darwin, {other_arch}\npackage app\n",
                "src/t_ignore.odin": "#+ignore\npackage app\n",
            })
            scan = run_cli("scan", proj, "--work-dir", work)
            self.assertEqual(scan.returncode, 0, scan.stderr)
            by_path = {s["path"]: s["darwin_active"] for s in json.loads(scan.stdout)["sources"]}
            self.assertTrue(by_path["src/t_or_ok.odin"])
            self.assertFalse(by_path["src/t_or_no.odin"])
            self.assertFalse(by_path["src/t_and_no.odin"])
            self.assertTrue(by_path["src/t_and_ok.odin"])
            self.assertFalse(by_path["src/t_arch_no.odin"])
            self.assertFalse(by_path["src/t_notdarwin.odin"])
            self.assertTrue(by_path["src/t_or_arch.odin"])
            self.assertFalse(by_path["src/t_ignore.odin"])

    def test_replay_tree_manifest_and_metadata_validation(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            write_files(proj, {
                "src/main.odin": '''package app
main :: proc() {
	assert(false, "startup assert")
}
''',
            })
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "10", "--max-cases", "5")
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            _, report = latest_report(work)
            fdir = Path(report["applications"][0]["findings"][0]["directory"])

            # 1. Injecting a symlink into initial/ must be rejected even if regular files match.
            injected_link = fdir / "initial" / "evil_link"
            os.symlink("/etc/hosts", injected_link)
            r_link = run_cli("reproduce", fdir)
            self.assertEqual(r_link.returncode, 2, r_link.stdout + r_link.stderr)
            injected_link.unlink()

            # 2. Injecting an extra directory into initial/ must be rejected.
            extra_dir = fdir / "initial" / "extra_dir"
            extra_dir.mkdir()
            r_dir = run_cli("reproduce", fdir)
            self.assertEqual(r_dir.returncode, 2, r_dir.stdout + r_dir.stderr)
            extra_dir.rmdir()

            # 3. Malicious finding.json app_config / env / bool timeout must be rejected BEFORE execution.
            meta_path = fdir / "finding.json"
            orig_meta = meta_path.read_text(encoding="utf-8")
            outside_write = Path(td) / "escaped_events.json"
            for mutator in (
                lambda m: m.update({"app_config": {"ui_events": {"mode": "file", "path": str(outside_write)}}}),
                lambda m: m.update({"app_config": {"ui_events": {"mode": "file", "path": "../../escaped.json"}}}),
                lambda m: m["environment"].update({"DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib"}),
                lambda m: m.update({"timeout": True}),
            ):
                m = json.loads(orig_meta)
                mutator(m)
                meta_path.write_text(json.dumps(m), encoding="utf-8")
                bad = run_cli("reproduce", fdir)
                self.assertEqual(bad.returncode, 2, bad.stdout + bad.stderr)
                self.assertFalse(outside_write.exists())
            meta_path.write_text(orig_meta, encoding="utf-8")
            self.assertEqual(run_cli("reproduce", fdir).returncode, 1)

            # 4. Non-object finding.json and ODIN_FUZZ_COV_FILE injection must also fail cleanly with exit 2.
            m_cov = json.loads(orig_meta)
            m_cov["environment"]["ODIN_FUZZ_COV_FILE"] = str(Path(td) / "evil.cov")
            meta_path.write_text(json.dumps(m_cov), encoding="utf-8")
            self.assertEqual(run_cli("reproduce", fdir).returncode, 2)
            meta_path.write_text("[]", encoding="utf-8")
            self.assertEqual(run_cli("reproduce", fdir).returncode, 2)
            meta_path.write_text(orig_meta, encoding="utf-8")

    def test_work_dir_inside_project_and_normalized_excludes(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = proj / "work"
            write_files(proj, {
                "src/main.odin": "package app\nmain :: proc() {}\n",
                "generated/main.odin": "package gen\nSYNTAX ERROR IF SCANNED !!!\n",
                "ignored_dir/main.odin": "package ign\nSYNTAX ERROR IF SCANNED !!!\n",
                "odin-fuzz.json": json.dumps({"exclude": ["generated/", "./ignored_dir"]}),
            })
            # Two consecutive runs with non-hidden work dir inside project must not recurse or find phantom apps.
            r1 = run_cli("explore", proj, "--work-dir", work, "--budget", "5", "--max-cases", "3")
            self.assertEqual(r1.returncode, 0, r1.stdout + r1.stderr)
            r2 = run_cli("explore", proj, "--work-dir", work, "--budget", "5", "--max-cases", "3")
            self.assertEqual(r2.returncode, 0, r2.stdout + r2.stderr)
            _, report = latest_report(work)
            self.assertEqual([a["path"] for a in report["applications"]], ["src"])

    def test_asan_spoof_rejection_and_site_normalization_with_initial_ancestor(self):
        # 1. Echoed ASan text with ordinary exit(1) must NOT become a confirmed bug (Finding 9).
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            write_files(proj, {
                "src/main.odin": '''package app
import "core:fmt"
import "core:os"
main :: proc() {
	fmt.eprintln("==999==ERROR: AddressSanitizer: heap-use-after-free on address 0x1")
	fmt.eprintln("SUMMARY: AddressSanitizer: heap-use-after-free src/main.odin:5 in app::main")
	os.exit(1)
}
''',
            })
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "6", "--max-cases", "5")
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            _, report = latest_report(work)
            self.assertEqual(report["applications"][0]["findings"], [])

        # 2. Ancestor directory named 'initial' must not break replay or drop ASan bug class (Finding 9).
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "initial"
            proj = base / "proj"
            work = base / "work"
            write_files(proj, {
                "src/main.odin": '''package app
import "core:fmt"
main :: proc() {
	p := new(int)
	free(p)
	p^ = 99
	fmt.println(p^)
}
''',
            })
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "10", "--max-cases", "5")
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            _, report = latest_report(work)
            finding = report["applications"][0]["findings"][0]
            self.assertEqual(finding["kind"], "address_sanitizer")
            self.assertIn("heap-use-after-free", finding["site"])
            rep = run_cli("reproduce", finding["directory"])
            self.assertEqual(rep.returncode, 1, rep.stdout + rep.stderr)

    def test_evolution_and_trace_cmp_untaken_branch_targeting(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            write_files(proj, {
                "src/main.odin": '''package app
import "core:os"
import "core:strconv"

main :: proc() {
	if len(os.args) < 2 { os.exit(1) }
	x, ok1 := strconv.parse_int(os.args[1])
	if !ok1 { os.exit(1) }
	if x != 31337 { os.exit(1) }
	if len(os.args) < 3 { os.exit(1) }
	y, ok2 := strconv.parse_int(os.args[2])
	if !ok2 { os.exit(1) }
	// 43682 is computed at runtime and never written as a literal in source.
	expected_y := x + 12345
	if y != expected_y { os.exit(1) }
	if len(os.args) < 4 { os.exit(1) }
	if os.args[3] == "DEEP_UNLOCK" {
		assert(false, "deep 3-stage branch bug")
	}
}
''',
            })
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "25", "--max-cases", "180", "--seed", "1")
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            _, report = latest_report(work)
            app_res = report["applications"][0]
            self.assertEqual(app_res["coverage_mode"], "llvm_sancov")
            self.assertGreater(app_res["first_party_edges_hit"], 0)
            self.assertGreaterEqual(app_res["corpus_size"], 2)
            self.assertGreater(app_res["targeted_executions"], 0)
            self.assertEqual(len(app_res["findings"]), 1)
            rep = run_cli("reproduce", app_res["findings"][0]["directory"])
            self.assertEqual(rep.returncode, 1, rep.stdout + rep.stderr)

    def test_evolution_guided_multi_button_ui_sequence(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            write_files(proj, {
                "src/main.odin": '''package app
import "core:encoding/json"
import "core:os"

Frame_Event :: struct {
	frame:        int,
	keys_pressed: []string,
	close:        bool,
}

main :: proc() {
	if len(os.args) < 2 { os.exit(1) }
	data, err := os.read_entire_file(os.args[1], context.allocator)
	if err != nil { os.exit(1) }
	defer delete(data)
	events: []Frame_Event
	if json.unmarshal(data, &events) != nil { os.exit(1) }
	stage := 0
	for ev in events {
		for k in ev.keys_pressed {
			if stage == 0 && k == "A" {
				stage = 1
			} else if stage == 1 && k == "B" {
				stage = 2
			} else if stage == 2 && k == "C" {
				stage = 3
			} else if stage == 3 && k == "D" {
				assert(false, "4-button ordered sequence bug")
			} else {
				stage = 0
			}
		}
		if ev.close { break }
	}
}
''',
                "odin-fuzz.json": json.dumps({
                    "applications": [{
                        "path": "src",
                        "name": "combo-ui",
                        "args": ["{events}"],
                        "ui_events": {
                            "mode": "file",
                            "path": "events.json",
                            "keys": ["A", "B", "C", "D", "E", "F", "G", "H"],
                            "max_frames": 12,
                        },
                    }]
                }),
            })
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "25", "--max-cases", "150", "--seed", "1")
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            _, report = latest_report(work)
            app_res = report["applications"][0]
            self.assertEqual(app_res["coverage_mode"], "llvm_sancov")
            self.assertGreaterEqual(app_res["corpus_size"], 3)
            self.assertEqual(len(app_res["findings"]), 1)
            rep = run_cli("reproduce", app_res["findings"][0]["directory"])
            self.assertEqual(rep.returncode, 1, rep.stdout + rep.stderr)

    def test_dynamic_string_cmp_and_untaken_frontier_report(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            write_files(proj, {
                "src/main.odin": '''package app
import "core:os"
import "core:strings"

main :: proc() {
	if len(os.args) < 2 { os.exit(1) }
	// Dynamically constructed at runtime; never appears as a single literal in source.
	secret := strings.concatenate({"DYN_", "TOKEN_", "42"})
	defer delete(secret)
	if os.args[1] == "NEVER_MATCHES_FRONTIER_999" && len(os.args) > 10 {
		os.exit(0)
	}
	if os.args[1] == secret {
		assert(false, "dynamic string equality bug")
	}
}
''',
            })
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "20", "--max-cases", "60", "--seed", "1")
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            run_dir, report = latest_report(work)
            app_res = report["applications"][0]
            self.assertEqual(app_res["coverage_mode"], "llvm_sancov")
            self.assertEqual(len(app_res["findings"]), 1)
            self.assertTrue(app_res.get("untaken_frontier"))
            self.assertTrue(any("NEVER_MATCHES_FRONTIER_999" in (b.get("clues") or []) for b in app_res["untaken_frontier"]))
            report_md = (run_dir / "report.md").read_text()
            self.assertIn("## Untaken frontier branches", report_md)
            self.assertIn("NEVER_MATCHES_FRONTIER_999", report_md)
            rep = run_cli("reproduce", app_res["findings"][0]["directory"])
            self.assertEqual(rep.returncode, 1, rep.stdout + rep.stderr)

    def test_ast_schema_guided_json_commands(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            write_files(proj, {
                "src/main.odin": '''package app
import "core:encoding/json"
import "core:os"

Op :: enum {
	Boot,
	Arm,
	Trigger,
}

Cmd :: struct {
	op:   Op,
	slot: int,
}

main :: proc() {
	if len(os.args) < 2 { os.exit(1) }
	data, err := os.read_entire_file(os.args[1], context.allocator)
	if err != nil { os.exit(1) }
	defer delete(data)
	cmds: []Cmd
	if json.unmarshal(data, &cmds) != nil { os.exit(1) }
	armed := false
	for c in cmds {
		if c.op == .Arm {
			armed = true
		} else if c.op == .Trigger && armed {
			assert(false, "schema-guided json command sequence bug")
		}
	}
}
''',
                "odin-fuzz.json": json.dumps({
                    "applications": [{
                        "path": "src",
                        "name": "schema-cmd",
                        "args": ["{file}"],
                        "files": ["commands.json"],
                    }]
                }),
            })
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "25", "--max-cases", "120", "--seed", "1")
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            _, report = latest_report(work)
            app_res = report["applications"][0]
            self.assertEqual(len(app_res["findings"]), 1)
            rep = run_cli("reproduce", app_res["findings"][0]["directory"])
            self.assertEqual(rep.returncode, 1, rep.stdout + rep.stderr)

    def test_confirmed_finding_minimization_and_persistent_corpus(self):
        # 1. Persistent corpus across runs (--corpus-dir).
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work1 = Path(td) / "work1"
            work2 = Path(td) / "work2"
            corpus = Path(td) / "corpus"
            write_files(proj, {
                "src/main.odin": '''package app
import "core:os"

main :: proc() {
	if len(os.args) < 2 { os.exit(1) }
	if os.args[1] == "STAGE_ALPHA" {
		if len(os.args) >= 3 && os.args[2] == "STAGE_BETA" {
			os.exit(0)
		}
		os.exit(0)
	}
	os.exit(1)
}
''',
            })
            res1 = run_cli("explore", proj, "--work-dir", work1, "--corpus-dir", corpus, "--budget", "15", "--max-cases", "40", "--seed", "1")
            self.assertEqual(res1.returncode, 0, res1.stdout + res1.stderr)
            _, rep1 = latest_report(work1)
            app1 = rep1["applications"][0]
            self.assertGreater(app1["corpus_saved"], 0)
            self.assertEqual(app1["corpus_loaded"], 0)

            # A corrupt corpus entry with non-string base64 field must be skipped, not abort explore.
            app_corpus_dir = next(corpus.iterdir())
            (app_corpus_dir / "corrupt.json").write_text(json.dumps({"argv": [], "stdin": 123, "files": {}, "environment": {}}), encoding="utf-8")

            res2 = run_cli("explore", proj, "--work-dir", work2, "--corpus-dir", corpus, "--budget", "15", "--max-cases", "15", "--seed", "99")
            self.assertEqual(res2.returncode, 0, res2.stdout + res2.stderr)
            _, rep2 = latest_report(work2)
            app2 = rep2["applications"][0]
            self.assertEqual(app2["corpus_loaded"], app1["corpus_saved"])
            self.assertGreaterEqual(app2["first_party_edges_hit"], app1["first_party_edges_hit"])

        # 2. Input shrinking on confirmed finding removes unused files/args/env and still reproduces.
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            write_files(proj, {
                "src/main.odin": '''package app
import "core:os"

main :: proc() {
	_ = os.get_env("EXTRA_ENV", context.allocator)
	for a in os.args[1:] {
		if a == "BOOM" {
			assert(false, "shrinkable finding")
		}
	}
}
''',
            })
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "15", "--max-cases", "40", "--seed", "1")
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            _, report = latest_report(work)
            finding = report["applications"][0]["findings"][0]
            case_data = json.loads((Path(finding["directory"]) / "case.json").read_text())
            self.assertEqual(len(case_data["steps"]), 1)
            self.assertEqual(case_data["steps"][0]["argv"], ["BOOM"])
            self.assertEqual(case_data["steps"][0]["files"], {})
            self.assertEqual(case_data["steps"][0]["environment"], {})
            self.assertEqual(case_data["steps"][0]["stdin"], "")
            rep = run_cli("reproduce", finding["directory"])
            self.assertEqual(rep.returncode, 1, rep.stdout + rep.stderr)

    def test_trust_boundary_hardening_replay_symlinks_ipc_cov_and_sandbox(self):
        import shutil
        import signal
        import socket
        import threading
        sys.path.insert(0, str(ROOT / "tools"))
        import odin_fuzz

        # 1. reproduce must reject symlinked replay/, finding.json, or case.json without touching targets.
        with tempfile.TemporaryDirectory() as td:
            td = Path(td).resolve()
            proj = td / "proj"
            work = td / "work"
            victim_dir = td / "victim_dir"
            victim_dir.mkdir()
            victim_file = victim_dir / "keep.txt"
            victim_file.write_text("DO_NOT_DELETE", encoding="utf-8")
            write_files(proj, {"src/main.odin": 'package app\nmain :: proc() { assert(false, "boom") }\n'})
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "10", "--max-cases", "5")
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            _, report = latest_report(work)
            fdir = Path(report["applications"][0]["findings"][0]["directory"])

            replay_link = fdir / "replay"
            os.symlink(victim_dir, replay_link)
            r_replay = run_cli("reproduce", fdir)
            self.assertEqual(r_replay.returncode, 2, r_replay.stdout + r_replay.stderr)
            self.assertTrue(victim_file.is_file())
            self.assertEqual(victim_file.read_text(encoding="utf-8"), "DO_NOT_DELETE")
            replay_link.unlink()

            orig_case = (fdir / "case.json").read_bytes()
            ext_case = td / "ext_case.json"
            ext_case.write_bytes(orig_case)
            (fdir / "case.json").unlink()
            os.symlink(ext_case, fdir / "case.json")
            self.assertEqual(run_cli("reproduce", fdir).returncode, 2)
            (fdir / "case.json").unlink()
            (fdir / "case.json").write_bytes(orig_case)

            orig_meta = (fdir / "finding.json").read_bytes()
            ext_meta = td / "ext_finding.json"
            ext_meta.write_bytes(orig_meta)
            (fdir / "finding.json").unlink()
            os.symlink(ext_meta, fdir / "finding.json")
            self.assertEqual(run_cli("reproduce", fdir).returncode, 2)
            (fdir / "finding.json").unlink()
            (fdir / "finding.json").write_bytes(orig_meta)
            self.assertEqual(run_cli("reproduce", fdir).returncode, 1)

        # 2. read_coverage(workspace=...) must refuse symlinked intermediate .tmp directory.
        with tempfile.TemporaryDirectory() as td:
            td = Path(td).resolve()
            ws = td / "ws"
            ws.mkdir()
            ext_dir = td / "ext_cov"
            ext_dir.mkdir()
            # Minimal valid OFC2 header + 1 edge record.
            import struct
            ofc2 = b"OFC2" + struct.pack("<III", 1, 0, 0) + struct.pack("<IQB", 1, 0x1000, 1)
            (ext_dir / "cov-0.bin").write_bytes(ofc2)
            os.symlink(ext_dir, ws / ".tmp")
            cov = odin_fuzz.read_coverage(ws / ".tmp" / "cov-0.bin", [], [], workspace=ws)
            self.assertEqual(cov["edges"], set())

        # 3. local_ipc client role must not connect through a target-created symlink to an external Unix socket,
        #    and must survive a target-created directory at sock_path across steps.
        short_base = Path(tempfile.mkdtemp(prefix="ofz_ipcsym_", dir="/tmp"))
        try:
            ext_sock = short_base / "host.sock"
            received = []
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(str(ext_sock))
            srv.listen(2)
            srv.settimeout(0.1)
            stop_srv = threading.Event()

            def accept_loop():
                while not stop_srv.is_set():
                    try:
                        conn, _ = srv.accept()
                    except (TimeoutError, socket.timeout):
                        continue
                    except OSError:
                        break
                    try:
                        received.append(conn.recv(256))
                    finally:
                        conn.close()

            t = threading.Thread(target=accept_loop, daemon=True)
            t.start()
            try:
                proj = short_base / "p"
                work = short_base / "w"
                write_files(proj, {
                    "src/main.odin": f'''package app
import "core:os"
import "core:sys/posix"
main :: proc() {{
	sock_path, ok := os.lookup_env("S", context.allocator)
	if !ok {{ os.exit(1) }}
	if len(os.args) > 1 && os.args[1] == "dir" {{
		_ = posix.mkdir(strings_clone_c(sock_path), {{.IRUSR, .IWUSR, .IXUSR}})
		return
	}}
	_ = posix.symlink({json.dumps(str(ext_sock))}, strings_clone_c(sock_path))
	// Give the host poll thread time to notice the symlink if it were vulnerable.
	ts := posix.timespec{{tv_sec = 0, tv_nsec = 150_000_000}}
	_ = posix.nanosleep(&ts, nil)
}}
strings_clone_c :: proc(s: string) -> cstring {{
	buf := make([]u8, len(s) + 1)
	copy(buf, s)
	return cstring(raw_data(buf))
}}
''',
                })
                chain = odin_fuzz.toolchain()
                initial = work / "initial"
                odin_fuzz.snapshot_tree(proj, initial)
                odin_fuzz.build_application({"path": "src"}, initial, chain, odin_fuzz.project_settings(proj), work)
                env = {**odin_fuzz.BASE_ENV, "ASAN_OPTIONS": odin_fuzz.ASAN_OPTIONS}
                app_cfg = {"local_ipc": {"role": "client", "socket_env": "S"}}
                case = {
                    "steps": [
                        {"argv": ["dir"], "stdin": "", "files": {}, "environment": {}, "ipc_messages": [odin_fuzz.encode(b"SHOULD_NOT_ARRIVE")]},
                        {"argv": ["sym"], "stdin": "", "files": {}, "environment": {}, "ipc_messages": [odin_fuzz.encode(b"SHOULD_NOT_ARRIVE")]},
                    ]
                }
                res = odin_fuzz.execute_case(initial, case, work / "scratch", env, 5.0, app_cfg)
                self.assertEqual(res["returncode"], 0)
                self.assertEqual(received, [])

                # Replacing the entire socket directory must not redirect host cleanup or the next step.
                outside_dir = short_base / "outside"
                outside_dir.mkdir(mode=0o755)
                outside_file = outside_dir / "s"
                outside_file.write_text("KEEP", encoding="utf-8")
                outside_mode = outside_dir.stat().st_mode
                swap_scratch = short_base / "swap"
                with odin_fuzz.local_ipc_fixture({"role": "client"}, swap_scratch, [], 0.2) as (_, sock_dir):
                    sock_dir.rmdir()
                    sock_dir.symlink_to(outside_dir, target_is_directory=True)
                self.assertEqual(outside_file.read_text(encoding="utf-8"), "KEEP")
                self.assertEqual(outside_dir.stat().st_mode, outside_mode)
                with odin_fuzz.local_ipc_fixture({"role": "client"}, swap_scratch, [], 0.2) as (_, sock_dir):
                    self.assertFalse(sock_dir.is_symlink())
                self.assertEqual(outside_file.read_text(encoding="utf-8"), "KEEP")
            finally:
                stop_srv.set()
                srv.close()
                t.join(timeout=1.0)
        finally:
            shutil.rmtree(short_base, ignore_errors=True)

        # 4. Sandbox blocks cross-process signaling and external xattr reads.
        with tempfile.TemporaryDirectory() as td:
            td = Path(td).resolve()
            ws = td / "ws"
            ws.mkdir()
            outside = td / "outside.txt"
            outside.write_text("x", encoding="utf-8")
            subprocess.run(["/usr/bin/xattr", "-w", "user.probe", "SECRET_XATTR", str(outside)], check=True)
            sleeper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
            try:
                profile = odin_fuzz.sandbox_profile(ws)
                probe = (
                    "import ctypes, os, signal, sys\n"
                    f"try:\n os.kill({sleeper.pid}, signal.SIGTERM)\n sys.exit(10)\nexcept PermissionError:\n pass\n"
                    "libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)\n"
                    "buf = ctypes.create_string_buffer(64)\n"
                    f"n = libc.getxattr({str(outside)!r}.encode(), b'user.probe', buf, 64, 0, 0)\n"
                    "sys.exit(11 if n >= 0 else 0)\n"
                )
                r = subprocess.run(["/usr/bin/sandbox-exec", "-p", profile, sys.executable, "-c", probe],
                                   cwd=ws, capture_output=True, text=True, timeout=10)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIsNone(sleeper.poll())
            finally:
                if sleeper.poll() is None:
                    sleeper.kill()
                    sleeper.wait()

    def test_summary_json_clean_finding_and_error_runs(self):
        required_app_keys = {
            "name", "path", "status", "finding_count", "executions", "coverage_mode",
            "first_party_edges_hit", "corpus_loaded", "corpus_saved",
            "frontier_branches_remaining", "ordinary_or_unclassified_exits",
            "timeouts", "workspace_errors", "unconfirmed_withheld",
        }
        forbidden_tokens = (
            "SEGV", "_heap_free", "ASAN_OPTIONS", "UBSAN_OPTIONS",
            "AddressSanitizer", "heap-use-after-free", "PAYLOAD_MARKER_999",
            "SECRET_UNTAKEN_CLUE", "#0 0x", "SUMMARY:",
        )

        # 1. Clean run writes summary.json with status "ok" and high-level metrics only.
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            corpus = Path(td) / "corpus"
            write_files(proj, {
                "src/main.odin": '''package app
import "core:os"
main :: proc() {
	if len(os.args) > 10 && os.args[1] == "SECRET_UNTAKEN_CLUE" {
		os.exit(0)
	}
}
''',
            })
            res = run_cli("explore", proj, "--work-dir", work, "--corpus-dir", corpus, "--budget", "10", "--max-cases", "12", "--seed", "1")
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            run_dir, _ = latest_report(work)
            summary_path = run_dir / "summary.json"
            self.assertTrue(summary_path.is_file())
            self.assertIn(f"Summary: {summary_path}", res.stdout)
            summary_text = summary_path.read_text(encoding="utf-8")
            for token in forbidden_tokens:
                self.assertNotIn(token, summary_text)
                self.assertNotIn(token, res.stdout)
            summary = json.loads(summary_text)
            self.assertEqual(summary["status"], "ok")
            self.assertEqual(summary["finding_count"], 0)
            self.assertEqual(summary["finding_dirs"], [])
            self.assertEqual(summary["run_directory"], str(run_dir))
            self.assertEqual(summary["report_md"], str(run_dir / "report.md"))
            self.assertEqual(summary["report_json"], str(run_dir / "report.json"))
            self.assertEqual(len(summary["applications"]), 1)
            app_sum = summary["applications"][0]
            self.assertEqual(set(app_sum.keys()), required_app_keys)
            self.assertEqual(app_sum["status"], "explored")
            self.assertEqual(app_sum["finding_count"], 0)
            self.assertGreater(app_sum["executions"], 0)
            self.assertEqual(app_sum["coverage_mode"], "llvm_sancov")
            self.assertGreater(app_sum["first_party_edges_hit"], 0)
            self.assertEqual(app_sum["corpus_loaded"], 0)
            self.assertGreater(app_sum["corpus_saved"], 0)
            self.assertEqual(app_sum["timeouts"], 0)
            self.assertEqual(app_sum["unconfirmed_withheld"], 0)

        # 2. Confirmed ASan finding writes status "findings" without raw sanitizer sites or payloads,
        #    while keeping full diagnostics intact in report.md, report.json, and finding bundles.
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            write_files(proj, {
                "src/main.odin": '''package app
import "core:fmt"
import "core:os"
main :: proc() {
	if len(os.args) < 2 || os.args[1] != "PAYLOAD_MARKER_999" {
		os.exit(1)
	}
	p := new(int)
	free(p)
	p^ = 42
	fmt.println(p^)
}
''',
            })
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "15", "--max-cases", "60", "--seed", "1")
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            run_dir, report = latest_report(work)
            summary_path = run_dir / "summary.json"
            self.assertTrue(summary_path.is_file())
            self.assertIn(f"Summary: {summary_path}", res.stdout)
            summary_text = summary_path.read_text(encoding="utf-8")
            for token in forbidden_tokens:
                self.assertNotIn(token, summary_text)
                self.assertNotIn(token, res.stdout)
            summary = json.loads(summary_text)
            self.assertEqual(summary["status"], "findings")
            self.assertEqual(summary["finding_count"], 1)
            self.assertEqual(len(summary["finding_dirs"]), 1)
            fdir = Path(summary["finding_dirs"][0])
            self.assertTrue(fdir.is_dir())
            app_sum = summary["applications"][0]
            self.assertEqual(set(app_sum.keys()), required_app_keys)
            self.assertEqual(app_sum["status"], "explored")
            self.assertEqual(app_sum["finding_count"], 1)
            self.assertGreater(app_sum["executions"], 0)
            self.assertEqual(app_sum["coverage_mode"], "llvm_sancov")

            # Full diagnostics remain intact for humans and triage tools.
            finding = report["applications"][0]["findings"][0]
            self.assertEqual(finding["directory"], str(fdir))
            self.assertEqual(finding["kind"], "address_sanitizer")
            self.assertIn("heap-use-after-free", finding["site"])
            self.assertIn("heap-use-after-free", (run_dir / "report.md").read_text(encoding="utf-8"))
            self.assertTrue((fdir / "finding.json").is_file())
            self.assertTrue((fdir / "case.json").is_file())
            self.assertTrue((fdir / "REPLAY.md").is_file())
            self.assertIn("AddressSanitizer", (fdir / "observation-0-step-0.stderr").read_text(encoding="utf-8"))
            rep = run_cli("reproduce", fdir)
            self.assertEqual(rep.returncode, 1, rep.stdout + rep.stderr)

        # 3. Unsupported app writes status "error" with safe default counts.
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            work = Path(td) / "work"
            write_files(proj, {
                "src/main.odin": '''package app
import rl "vendor:raylib"
main :: proc() {
	_ = rl.WindowShouldClose()
}
''',
            })
            res = run_cli("explore", proj, "--work-dir", work, "--budget", "5", "--max-cases", "5")
            self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
            run_dir, _ = latest_report(work)
            summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["status"], "error")
            self.assertEqual(summary["finding_count"], 0)
            self.assertEqual(summary["finding_dirs"], [])
            app_sum = summary["applications"][0]
            self.assertEqual(set(app_sum.keys()), required_app_keys)
            self.assertEqual(app_sum["status"], "unsupported")
            self.assertEqual(app_sum["executions"], 0)
            self.assertEqual(app_sum["coverage_mode"], "none")
            self.assertEqual(app_sum["ordinary_or_unclassified_exits"], 0)
            self.assertEqual(app_sum["workspace_errors"], 0)

    def test_nix_toolchain_sandbox_and_scanner_resolution(self):
        from unittest import mock
        sys.path.insert(0, str(ROOT / "tools"))
        import odin_fuzz

        # 1. Clean-shell direct checkout invocation fails closed with exit 2 (no overrides, no local scanner build).
        clean_res = subprocess.run(
            [sys.executable, str(ROOT / "odin-fuzz"), "doctor"],
            env={"PATH": "/usr/bin:/bin"},
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(clean_res.returncode, 2, clean_res.stdout + clean_res.stderr)
        self.assertIn("direct unpackaged execution is disabled", clean_res.stderr)
        with mock.patch.dict(os.environ, {"ODIN_FUZZ_PACKAGED": ""}, clear=False):
            self.assertEqual(odin_fuzz.main(["doctor"]), 2)
            with self.assertRaises(odin_fuzz.ToolError):
                odin_fuzz.scanner({"odin_report": ""})

        # 2. Seatbelt profile permits /nix/store reads and BASE_ENV excludes Homebrew paths.
        with tempfile.TemporaryDirectory() as td:
            profile = odin_fuzz.sandbox_profile(Path(td))
            self.assertIn('(subpath "/nix/store")', profile)
            self.assertNotIn("/opt/homebrew", odin_fuzz.BASE_ENV["PATH"])
            self.assertNotIn("/usr/local", odin_fuzz.BASE_ENV["PATH"])

        # 3. Packaged provenance checks with harmless stand-ins (fail closed on ambient/mismatch/override).
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            fake_store = root / "nix-store"
            nix_bin = fake_store / "toolchain" / "bin"
            ambient_bin = root / "ambient" / "bin"
            pkg_root = fake_store / "odin-fuzz-pkg"
            pkg_share = pkg_root / "share" / "odin-fuzz"
            pkg_libexec = pkg_root / "libexec"
            for d in (nix_bin, ambient_bin, pkg_share, pkg_libexec):
                d.mkdir(parents=True)
            for name in ("odin", "clang", "llvm-symbolizer", "dsymutil", "nm"):
                (nix_bin / name).write_text("", encoding="utf-8")
                (ambient_bin / name).write_text("", encoding="utf-8")
            bundled_scan = pkg_libexec / "odin-fuzz-scan"
            bundled_scan.write_text("", encoding="utf-8")
            rogue_scan = root / "rogue-scan"
            rogue_scan.write_text("", encoding="utf-8")

            which_map = {name: str(nix_bin / name) for name in ("odin", "clang", "llvm-symbolizer", "dsymutil", "nm")}
            which_map[str(nix_bin / "odin")] = str(nix_bin / "odin")
            which_map[str(ambient_bin / "odin")] = str(ambient_bin / "odin")

            def is_fake_store(p):
                return bool(p) and str(Path(p).resolve()).startswith(str(fake_store) + "/")

            def fake_check_output(cmd, **kwargs):
                exe = str(cmd[0])
                if cmd[1] == "report":
                    return "Backend: LLVM 22.1.8\n"
                if exe == str(nix_bin / "clang"):
                    return "clang version 22.1.8\n"
                if exe == str(nix_bin / "llvm-symbolizer"):
                    return "LLVM version 22.1.8\n"
                if exe == str(nix_bin / "dsymutil"):
                    return "LLVM version 22.1.8\n"
                return "Apple LLVM version 17.0.0\n"

            with mock.patch.object(odin_fuzz, "is_nix_store_path", side_effect=is_fake_store), \
                 mock.patch.object(odin_fuzz, "ROOT", pkg_share), \
                 mock.patch.object(odin_fuzz.shutil, "which", side_effect=lambda n: which_map.get(n)), \
                 mock.patch.object(odin_fuzz.subprocess, "check_output", side_effect=fake_check_output):
                # Packaged happy path + identical --odin allowed.
                pkg_env = {"ODIN_FUZZ_PACKAGED": "1", "ODIN": str(nix_bin / "odin"), "ODIN_FUZZ_SCANNER": str(bundled_scan)}
                with mock.patch.dict(os.environ, pkg_env, clear=False):
                    chain = odin_fuzz.toolchain()
                    self.assertEqual(chain["odin"], str((nix_bin / "odin").resolve()))
                    self.assertEqual(chain["clang"], str((nix_bin / "clang").resolve()))
                    self.assertEqual(chain["dsymutil"], str((nix_bin / "dsymutil").resolve()))
                    chain_same = odin_fuzz.toolchain(str(nix_bin / "odin"))
                    self.assertEqual(chain_same["odin"], str((nix_bin / "odin").resolve()))
                    self.assertEqual(odin_fuzz.scanner({"odin_report": ""}), bundled_scan.resolve())
                    # Refuses different --odin override in packaged mode.
                    with self.assertRaises(odin_fuzz.ToolError):
                        odin_fuzz.toolchain(str(ambient_bin / "odin"))
                    # Refuses ODIN_FUZZ_SCANNER substitution in packaged mode.
                    with mock.patch.dict(os.environ, {**pkg_env, "ODIN_FUZZ_SCANNER": str(rogue_scan)}, clear=False):
                        with self.assertRaises(odin_fuzz.ToolError):
                            odin_fuzz.scanner({"odin_report": ""})

                # Refuses non-store ODIN in packaged mode.
                with mock.patch.dict(os.environ, {"ODIN_FUZZ_PACKAGED": "1", "ODIN": str(ambient_bin / "odin")}, clear=False):
                    with self.assertRaises(odin_fuzz.ToolError):
                        odin_fuzz.toolchain()

                # Refuses ambient (non-store) or Apple-mismatched LLVM tool on PATH (no Homebrew fallback).
                bad_which = {**which_map, "dsymutil": str(ambient_bin / "dsymutil")}
                with mock.patch.dict(os.environ, pkg_env, clear=False), \
                     mock.patch.object(odin_fuzz.shutil, "which", side_effect=lambda n: bad_which.get(n)):
                    with self.assertRaises(odin_fuzz.ToolError):
                        odin_fuzz.toolchain()

                # Refuses unpackaged mode even with valid store tools on PATH.
                with mock.patch.dict(os.environ, {"ODIN_FUZZ_PACKAGED": "", "ODIN": str(nix_bin / "odin")}, clear=False):
                    with self.assertRaises(odin_fuzz.ToolError):
                        odin_fuzz.toolchain()
                    with self.assertRaises(odin_fuzz.ToolError):
                        odin_fuzz.scanner({"odin_report": ""})


if __name__ == "__main__":
    unittest.main()
