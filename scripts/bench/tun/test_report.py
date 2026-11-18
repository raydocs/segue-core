"""Unit tests for the TUN benchmark report generator. No sockets, no routes."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import configs  # noqa: E402
import report  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]


class PsTimeTests(unittest.TestCase):
    def test_mm_ss_fraction(self):
        self.assertEqual(report.parse_ps_time_to_millis("0:00.02"), 20)
        self.assertEqual(report.parse_ps_time_to_millis("1:02.03"), 62030)

    def test_hh_mm_ss_and_days(self):
        self.assertEqual(report.parse_ps_time_to_millis("1:02:03"), 3723000)
        self.assertEqual(report.parse_ps_time_to_millis("1-00:00:01.5"), 86401500)

    def test_rejects_garbage(self):
        with self.assertRaises(report.ReportError):
            report.parse_ps_time_to_millis("nope")

    def test_ps_sample_line(self):
        parsed = report.parse_ps_sample("  2816   0:00.02\n")
        self.assertEqual(parsed["rss_kib"], 2816)
        self.assertEqual(parsed["cpu_millis"], 20)


class MetricTests(unittest.TestCase):
    def test_published_grpc_throughput(self):
        # 2026-11-18 segue gRPC median: 1 GiB in 329 ms -> 26110 Mbps.
        self.assertEqual(report.throughput_mbps(1073741824, 329), 26110)

    def test_throughput_empty(self):
        self.assertIsNone(report.throughput_mbps(0, 329))
        self.assertIsNone(report.throughput_mbps(100, 0))

    def test_cpu_per_gib_exact(self):
        self.assertEqual(report.cpu_ms_per_gib(540, 1073741824), 540)

    def test_cpu_per_gib_rounds_up(self):
        self.assertEqual(report.cpu_ms_per_gib(1, 1073741824), 1)
        self.assertIsNone(report.cpu_ms_per_gib(10, 0))

    def test_nearest_rank(self):
        self.assertEqual(report.percentile_nearest_rank([10, 20, 30, 40], 50), 20)
        self.assertEqual(report.percentile_nearest_rank(list(range(100)), 99), 98)
        self.assertIsNone(report.percentile_nearest_rank([], 50))

    def test_median_upper_matches_phase_memory_index(self):
        self.assertEqual(report.median_upper([1, 2, 3, 4]), 3)
        self.assertEqual(report.median_upper([1, 2, 3]), 2)

    def test_summarize_samples(self):
        summary = report.summarize_samples(
            [
                {"rss_kib": 10, "cpu_millis": 100},
                {"rss_kib": 30, "cpu_millis": 140},
                {"rss_kib": 20, "cpu_millis": 250},
            ]
        )
        self.assertEqual(summary["first_rss_kib"], 10)
        self.assertEqual(summary["median_rss_kib"], 20)
        self.assertEqual(summary["peak_rss_kib"], 30)
        self.assertEqual(summary["last_rss_kib"], 20)
        self.assertEqual(summary["cpu_ms"], 150)

    def test_cpu_does_not_go_backwards(self):
        summary = report.summarize_samples(
            [
                {"rss_kib": 1, "cpu_millis": 50},
                {"rss_kib": 1, "cpu_millis": 10},
            ]
        )
        self.assertEqual(summary["cpu_ms"], 0)

    def test_empty_samples(self):
        summary = report.summarize_samples([])
        self.assertEqual(summary["samples"], 0)
        self.assertIsNone(summary["cpu_ms"])


class ImpairmentTests(unittest.TestCase):
    def test_bulk_bytes(self):
        self.assertEqual(report.bulk_bytes("clean", 100, 8), 100)
        self.assertEqual(report.bulk_bytes("rtt50", 100, 8), 100)
        self.assertEqual(report.bulk_bytes("rtt50-loss1", 100, 8), 8)
        self.assertEqual(report.bulk_bytes("rtt150-loss3", 100, 8), 8)

    def test_dnctl_clean_is_empty(self):
        self.assertEqual(report.dnctl_argv("clean", 7), [])

    def test_dnctl_delay_fits_the_queue_limit(self):
        self.assertEqual(
            report.dnctl_argv("rtt50", 7),
            ["pipe", "7", "config", "delay", "25", "plr", "0", "bw", "200Mbit/s", "queue", "900Kbytes"],
        )
        self.assertEqual(
            report.dnctl_argv("rtt150-loss3", 7),
            ["pipe", "7", "config", "delay", "75", "plr", "0.03", "bw", "80Mbit/s", "queue", "900Kbytes"],
        )

    def test_pf_rules_are_stateless_and_both_directions(self):
        text = report.pf_rules(24443, 7)
        self.assertEqual(text.count("no state pipe 7"), 2)
        self.assertIn("to 127.0.0.1 port 24443", text)
        self.assertIn("from 127.0.0.1 port 24443", text)
        self.assertNotIn("keep state", text)

    def test_pf_patch_comments_lo0_and_is_idempotent(self):
        original = "set skip on lo0\nset skip on en0\nanchor \"com.apple/*\"\n"
        patched = report.pf_ruleset_for_bench(original, "segue.tunbench")
        self.assertNotIn("\nset skip on lo0\n", "\n" + patched)
        self.assertIn("# set skip on lo0", patched)
        self.assertIn("set skip on en0", patched)
        self.assertIn('dummynet-anchor "segue.tunbench"', patched)
        self.assertIn('anchor "segue.tunbench"', patched)
        self.assertEqual(report.pf_ruleset_for_bench(patched, "segue.tunbench"), patched)

    def test_pf_patch_rejects_a_nested_anchor(self):
        with self.assertRaises(report.ReportError):
            report.pf_ruleset_for_bench("set skip on lo0\n", "com.apple/segue.tunbench")


class RouteTests(unittest.TestCase):
    BEFORE = "Destination Gateway Flags Netif Expire\ndefault 192.0.2.1 UGSc en0\n"
    AFTER = BEFORE + "0/1 172.19.0.2 UGSc utun4\n198.51.100.20 172.19.0.2 UGHS utun4\n"

    def test_deletes_only_new_utun_routes(self):
        rows = report.leftover_tun_routes(self.BEFORE, self.AFTER)
        self.assertEqual(rows, [["v4", "0/1", "172.19.0.2"], ["v4", "198.51.100.20", "172.19.0.2"]])

    def test_leaves_a_route_that_was_already_there(self):
        self.assertEqual(report.leftover_tun_routes(self.AFTER, self.AFTER), [])

    def test_ignores_the_system_default(self):
        text = "Destination Gateway Flags Netif Expire\ndefault 192.0.2.1 UGSc en0\n"
        self.assertEqual(report.leftover_tun_routes("", text), [])


class ReportRenderTests(unittest.TestCase):
    def cell(self, **overrides):
        base = {
            "engine": "segue-kernel",
            "protocol": "reality",
            "impairment": "clean",
            "workload": "bulk-1",
            "ok": True,
            "error": None,
            "bytes": 1073741824,
            "bytes_requested": 1073741824,
            "duration_ms": 329,
            "ttfb_ms": 10.2,
            "ttfb_samples_us": [10200],
            "latency_us": [],
            "samples": [
                {"elapsed_ms": 0, "rss_kib": 14000, "cpu_millis": 10},
                {"elapsed_ms": 329, "rss_kib": 14256, "cpu_millis": 550},
            ],
        }
        base.update(overrides)
        return base

    def test_marked_report_round_trip(self):
        meta = {"generated_at": "2026-11-18T00:00:00Z", "dry_run": False, "full_bytes": 1073741824}
        marked = report.render_marked(report.build_report(meta, [self.cell()]))
        self.assertTrue(marked.startswith(report.MARK_BEGIN + "\n"))
        self.assertTrue(marked.rstrip().endswith(report.MARK_END))
        parsed = report.extract_json(marked)
        self.assertEqual(parsed["schema"], report.SCHEMA)
        cell = parsed["cells"][0]
        self.assertEqual(cell["throughput_mbps"], 26110)
        self.assertEqual(cell["cpu_ms"], 540)
        self.assertEqual(cell["cpu_ms_per_gib"], 540)
        self.assertEqual(cell["rss_kib"]["peak"], 14256)
        self.assertNotIn("samples", cell)
        self.assertNotIn("latency_us", cell)
        self.assertIn("| segue-kernel | reality | clean | bulk-1 | ok |", marked)

    def test_failed_cell_is_visible(self):
        meta = {"generated_at": "t", "dry_run": False}
        cell = self.cell(ok=False, error="probe failed\nwith a pipe", bytes=0, duration_ms=0)
        marked = report.render_marked(report.build_report(meta, [cell]))
        parsed = report.extract_json(marked)
        self.assertEqual(parsed["failed"], 1)
        self.assertEqual(parsed["cells"][0]["status"], "fail")
        self.assertIn("probe failed with a pipe", marked)
        self.assertNotIn("probe failed\nwith", marked.split(report.MARK_BEGIN, 1)[1].split("|")[0])

    def test_tcp_rr_percentiles_and_no_fake_throughput(self):
        meta = {"generated_at": "t", "dry_run": False}
        cell = self.cell(workload="tcp-rr", bytes=4, duration_ms=20, latency_us=[10, 20, 30, 40], ttfb_ms=None)
        parsed = report.extract_json(report.render_marked(report.build_report(meta, [cell])))
        row = parsed["cells"][0]
        self.assertEqual(row["latency_p50_us"], 20)
        self.assertEqual(row["latency_p99_us"], 40)
        self.assertIsNone(row["throughput_mbps"])
        self.assertIsNone(row["cpu_ms_per_gib"])

    def test_plan_orders_the_matrix(self):
        cells = report.planned_cells(
            ["mihomo-mixed", "segue-kernel"],
            ["grpc", "reality"],
            ["rtt150-loss3", "clean"],
            ["ttfb", "bulk-1"],
            100,
            8,
            200,
            20,
        )
        report_doc = report.build_report({"generated_at": "dry-run", "dry_run": True}, cells)
        order = [(c["engine"], c["protocol"], c["impairment"], c["workload"]) for c in report_doc["cells"]]
        self.assertEqual(
            order,
            [
                ("segue-kernel", "reality", "clean", "bulk-1"),
                ("segue-kernel", "reality", "clean", "ttfb"),
                ("segue-kernel", "reality", "rtt150-loss3", "bulk-1"),
                ("segue-kernel", "reality", "rtt150-loss3", "ttfb"),
                ("segue-kernel", "grpc", "clean", "bulk-1"),
                ("segue-kernel", "grpc", "clean", "ttfb"),
                ("segue-kernel", "grpc", "rtt150-loss3", "bulk-1"),
                ("segue-kernel", "grpc", "rtt150-loss3", "ttfb"),
                ("mihomo-mixed", "reality", "clean", "bulk-1"),
                ("mihomo-mixed", "reality", "clean", "ttfb"),
                ("mihomo-mixed", "reality", "rtt150-loss3", "bulk-1"),
                ("mihomo-mixed", "reality", "rtt150-loss3", "ttfb"),
                ("mihomo-mixed", "grpc", "clean", "bulk-1"),
                ("mihomo-mixed", "grpc", "clean", "ttfb"),
                ("mihomo-mixed", "grpc", "rtt150-loss3", "bulk-1"),
                ("mihomo-mixed", "grpc", "rtt150-loss3", "ttfb"),
            ],
        )
        clean = report_doc["cells"][0]
        lossy = report_doc["cells"][2]
        self.assertEqual(clean["bytes_requested"], 100)
        self.assertEqual(lossy["bytes_requested"], 8)
        self.assertEqual(report_doc["cells"][1]["iterations"], 20)


class ConfigTests(unittest.TestCase):
    def test_keys_match_segue_bench(self):
        text = (ROOT / "crates/segue-bench/src/lib.rs").read_text(encoding="utf-8")
        self.assertIn('const TEST_VLESS_UUID_STRING: &str = "{0}";'.format(configs.UUID), text)
        self.assertIn('const REALITY_PUBLIC_KEY: &str = "{0}";'.format(configs.REALITY_PUBLIC_KEY), text)
        self.assertIn('const REALITY_PRIVATE_KEY: &str = "{0}";'.format(configs.REALITY_PRIVATE_KEY), text)
        self.assertIn('const REALITY_SHORT_ID_HEX: &str = "{0}";'.format(configs.REALITY_SHORT_ID), text)
        self.assertIn('const GRPC_BENCH_SERVICE_NAME: &str = "{0}";'.format(configs.GRPC_SERVICE), text)

    def test_xray_redirects_to_the_sink(self):
        doc = json.loads(configs.xray_server(24443, 24444, "127.0.0.1:5001"))
        self.assertEqual(doc["outbounds"][0]["settings"]["redirect"], "127.0.0.1:5001")
        self.assertEqual(doc["inbounds"][0]["streamSettings"]["realitySettings"]["dest"], "127.0.0.1:5001")
        networks = [item["streamSettings"]["network"] for item in doc["inbounds"]]
        self.assertEqual(networks, ["tcp", "grpc"])

    def test_kernel_proxies_only_the_documentation_address(self):
        doc = json.loads(configs.kernel_config("reality", 24443))
        self.assertFalse(doc["tun"]["ipv6"])
        self.assertEqual(doc["default"], {"type": "direct"})
        self.assertEqual(doc["rules"][0]["ip_cidr"], "198.51.100.20/32")
        self.assertNotIn("flow", json.dumps(configs.kernel_config("grpc", 24444)))

    def test_singbox_excludes_loopback_and_autoroutes(self):
        doc = json.loads(configs.singbox_config("reality", 24443))
        tun = doc["inbounds"][0]
        self.assertTrue(tun["auto_route"])
        self.assertIn("127.0.0.0/8", tun["route_exclude_address"])
        self.assertEqual(doc["route"]["final"], "direct")
        grpc = json.loads(configs.singbox_config("grpc", 24444))
        self.assertNotIn("flow", grpc["outbounds"][0])
        self.assertEqual(grpc["outbounds"][0]["transport"]["service_name"], "bench")

    def test_mihomo_stacks(self):
        system = configs.mihomo_config("reality", "system", 24443)
        mixed = configs.mihomo_config("grpc", "mixed", 24444)
        self.assertIn("stack: system\n", system)
        self.assertIn("stack: mixed\n", mixed)
        self.assertIn("enable: true\n", system)
        self.assertIn("dns-hijack: []\n", system)
        self.assertIn("IP-CIDR,198.51.100.20/32,proxy,no-resolve", system)
        self.assertNotIn("flow:", mixed)
        self.assertIn("grpc-service-name: bench", mixed)


if __name__ == "__main__":
    unittest.main()
