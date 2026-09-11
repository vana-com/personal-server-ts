#!/usr/bin/env python3
"""Unit tests for the pure half of render-fleet.py: `python3 render-fleet.test.py`.

Nothing here calls phala; staging is exercised on the fleet, not in tests.
"""

import importlib.util
import json
import pathlib
import unittest

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
COMPOSE_DIR = REPO / "deploy" / "dstack"
MANIFEST = REPO / "deploy" / "dstack" / "fleets" / "preview-prod5.json"

SPKI = "MCowBQYDK2VwAyEAPPx3xJ6NkAsPk1gT2v9E3s/huSL9MVG3S9D8e/Eqzjg="
GIT_REF = "5bb959976edaf575b67738afbfb783d0498da4d2"
IMAGES = {
    "AGENT_IMAGE": "vanaorg/personal-server-enclave@sha256:" + "1" * 64,
    "RUNTIME_IMAGE": "vanaorg/personal-server-sandbox-runtime@sha256:" + "2" * 64,
    "PS_IMAGE": "vanaorg/personal-server@sha256:" + "3" * 64,
}


def load_module():
    spec = importlib.util.spec_from_file_location("render_fleet", HERE / "render-fleet.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


rf = load_module()


def rendered(name, overlay=None):
    text = (COMPOSE_DIR / name).read_text()
    if overlay:
        text = rf.merge_compose(text, (COMPOSE_DIR / overlay).read_text())

    return rf.render_compose(text, IMAGES, GIT_REF, SPKI)


class ComposeRendering(unittest.TestCase):
    def test_worker_markers_resolved(self):
        text = rendered("docker-compose.fleet-worker.yml")

        self.assertNotIn("image: REPLACE_WITH_", text)
        self.assertIn("GIT_REF='%s'" % GIT_REF, text)
        self.assertIn(IMAGES["PS_IMAGE"], text)

    def test_overlay_merges_sections(self):
        text = rendered("docker-compose.fleet-worker.yml", "docker-compose.fleet-worker-source.yml")
        _, sections = rf.split_sections(text)
        keys = [key for key, _ in sections]

        self.assertEqual(keys, ["services", "volumes"])
        self.assertIn("  mcp-tls:", text)
        self.assertIn("  mcp-certificates: null", text)
        self.assertIn("  mcp-state: null", text)

    def test_overlay_rejects_redefinition(self):
        base = "services:\n  agent:\n    image: a\n"

        with self.assertRaises(SystemExit):
            rf.merge_compose(base, base)

    def test_service_env_is_the_signed_pair(self):
        text = rendered("docker-compose.fleet-worker.yml")

        self.assertEqual(
            rf.service_env(text, "agent"),
            ["FLEET_CONFIG_PUBLIC_KEY=%s" % SPKI, "FLEET_SIGNED_CONFIG"],
        )
        # The runtime's environment is a mapping, so no signed pair is read.
        self.assertEqual(rf.service_env(text, "sandbox-runtime"), [])


class Assertions(unittest.TestCase):
    def check(self, text, service="agent"):
        rf.assert_compose("t.yml", text, IMAGES, GIT_REF, SPKI, service)

    def test_accepts_the_repo_composes(self):
        self.check(rendered("docker-compose.fleet-worker.yml"))
        self.check(rendered("docker-compose.fleet-controller.yml"), "controller")

    def test_rejects_unresolved_marker(self):
        text = rendered("docker-compose.fleet-worker.yml").replace(
            IMAGES["AGENT_IMAGE"], "REPLACE_WITH_REVIEWED_AGENT_IMAGE_DIGEST"
        )

        with self.assertRaises(SystemExit):
            self.check(text)

    def test_rejects_outer_interpolation(self):
        text = rendered("docker-compose.fleet-worker.yml").replace(
            "working_dir: /app", "working_dir: ${APP_DIR}"
        )

        with self.assertRaises(SystemExit):
            self.check(text)

    def test_rejects_a_tag_pinned_image(self):
        text = rendered("docker-compose.fleet-worker.yml").replace(
            IMAGES["RUNTIME_IMAGE"], "vanaorg/personal-server-sandbox-runtime:latest"
        )

        with self.assertRaises(SystemExit):
            self.check(text)

    def test_rejects_a_missing_git_ref(self):
        text = rendered("docker-compose.fleet-worker.yml").replace(GIT_REF, "0" * 40)

        with self.assertRaises(SystemExit):
            self.check(text)

    def test_rejects_an_extra_allowed_env(self):
        text = rendered("docker-compose.fleet-worker.yml").replace(
            "      - FLEET_SIGNED_CONFIG", "      - FLEET_SIGNED_CONFIG\n      - NODE_SECRET"
        )

        with self.assertRaises(SystemExit):
            self.check(text)


class Drafts(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(MANIFEST.read_text())
        self.nodes = self.manifest["nodes"]
        self.hashes = {n: v["pinned"]["composeHash"] for n, v in self.nodes.items()}

    def draft(self, name, staged=()):
        return rf.build_draft(
            self.manifest, self.nodes, name, IMAGES, self.hashes, staged, "2026-09-11T00:00:00.000Z"
        )

    def test_worker_draft_shape(self):
        draft = self.draft("worker-1")

        self.assertEqual(draft["purpose"], rf.CONFIG_PURPOSE)
        self.assertIsNone(draft["expiresAt"])
        self.assertEqual(draft["env"]["PS_IMAGE"], IMAGES["PS_IMAGE"])
        self.assertEqual(draft["secretRefs"], self.nodes["worker-1"]["secretRefs"])

    def test_staged_reciprocal_pins(self):
        old = "a" * 64
        peers = json.loads(self.draft("worker-1", staged=[old])["env"]["FLEET_PEER_POLICIES"])

        self.assertEqual([p["identity"]["role"] for p in peers], ["controller", "controller"])
        self.assertEqual(peers[0]["identity"]["composeHash"], old)
        self.assertEqual(peers[1]["identity"]["composeHash"], self.hashes["controller"])

    def test_pins_deduplicate(self):
        peers = json.loads(self.draft("worker-1")["env"]["FLEET_PEER_POLICIES"])

        self.assertEqual(len(peers), 1)

    def test_controller_directory(self):
        workers = json.loads(self.draft("controller")["env"]["FLEET_WORKERS_JSON"])
        first = workers[0]

        self.assertEqual(len(workers), 4)
        self.assertEqual(first["capacity"], self.nodes["worker-1"]["capacity"])
        self.assertEqual(first["policy"]["identity"]["composeHash"], self.hashes["worker-1"])
        self.assertTrue(first["url"].endswith(".%s" % self.manifest["gatewayDomain"]))

    def test_manifest_carries_no_secrets(self):
        for node in self.nodes.values():
            self.assertNotIn("PS_IMAGE", node["env"])
            for key in node["env"]:
                self.assertNotIn("SECRET", key)
                self.assertNotIn("TOKEN", key)

    def test_rejects_interpolated_env(self):
        self.nodes["worker-1"]["env"]["GATEWAY_URL"] = "${GATEWAY_URL}"

        with self.assertRaises(SystemExit):
            self.draft("worker-1")


if __name__ == "__main__":
    unittest.main()
