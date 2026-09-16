#!/usr/bin/env python3
"""Unit tests for the pure half of render-fleet.py: `python3 render-fleet.test.py`.

Nothing here calls phala; staging is exercised on the fleet, not in tests.
"""

import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
COMPOSE_DIR = REPO / "deploy" / "dstack"
MANIFEST = REPO / "deploy" / "dstack" / "fleets" / "preview-prod5.json"
TEMPLATE = REPO / "deploy" / "dstack" / "fleets" / "mainnet-prod1.json"

SPKI = "MCowBQYDK2VwAyEAPPx3xJ6NkAsPk1gT2v9E3s/huSL9MVG3S9D8e/Eqzjg="
GATEWAY_DOMAIN = "dstack-pha-prod5.phala.network"
MCP_DOMAIN = "mcp-dev.vana.org"
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
STAGE_NODE = rf.stage_node


def rendered(name, overlay=None):
    text = (COMPOSE_DIR / name).read_text()
    if overlay:
        text = rf.merge_compose(text, (COMPOSE_DIR / overlay).read_text())

    return rf.render_compose(text, IMAGES, GIT_REF, SPKI, GATEWAY_DOMAIN, MCP_DOMAIN)


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


class GatewayDomain(unittest.TestCase):
    def test_it_follows_the_manifest_not_the_compose(self):
        # It was a prod5 literal, so every non-Moksha fleet's mcp-tls waited on
        # Moksha's domain and never got a certificate for its own host.
        text = rf.render_compose(
            (COMPOSE_DIR / "docker-compose.fleet-controller.yml").read_text(),
            IMAGES, GIT_REF, SPKI, "dstack-pha-prod9.phala.network", "mcp.vana.org",
        )

        self.assertIn("GATEWAY_DOMAIN=_.dstack-pha-prod9.phala.network", text)
        self.assertNotIn("prod5", text)

    def test_moksha_renders_the_value_it_already_runs(self):
        # The fix must not move the live fleet: same bytes, same compose hash.
        text = rendered("docker-compose.fleet-controller.yml")

        self.assertIn("GATEWAY_DOMAIN=_.dstack-pha-prod5.phala.network", text)


class GatewayDomainFence(unittest.TestCase):
    def test_a_newline_cannot_inject_a_second_endpoint(self):
        # Codex demonstrated this against the first version of the fix: the
        # injected TARGET_ENDPOINT rendered and assert_compose accepted it.
        with self.assertRaises(SystemExit):
            rf.canonical_gateway_domain(
                "good.example\n      - TARGET_ENDPOINT=attacker.invalid:443"
            )

    def test_a_duplicate_singleton_key_is_refused(self):
        text = rendered("docker-compose.fleet-controller.yml")
        doubled = text.replace(
            "      - TARGET_ENDPOINT=controller:8788",
            "      - TARGET_ENDPOINT=controller:8788\n      - TARGET_ENDPOINT=x:1",
            1,
        )

        with self.assertRaises(SystemExit) as raised:
            rf.assert_compose("c.yml", doubled, IMAGES, GIT_REF, SPKI, "controller")

        self.assertIn("TARGET_ENDPOINT", str(raised.exception))

    def test_the_prefixed_form_does_not_double(self):
        self.assertEqual(
            rf.canonical_gateway_domain("_.dstack-pha-prod9.phala.network"),
            "dstack-pha-prod9.phala.network",
        )

    def test_a_trailing_dot_is_dropped(self):
        self.assertEqual(
            rf.canonical_gateway_domain("dstack-pha-prod9.phala.network."),
            "dstack-pha-prod9.phala.network",
        )

    def test_empty_and_missing_are_refused(self):
        for value in ["", "   ", "_.", None, 42, "no-dot", "UPPER.example"]:
            with self.assertRaises(SystemExit):
                rf.canonical_gateway_domain(value)


class McpDomain(unittest.TestCase):
    def test_the_cert_subject_follows_the_node(self):
        # DOMAIN is the name Let's Encrypt is asked to certify. It was pinned to
        # Moksha's host, so a mainnet controller asked for a cert it could never
        # validate and served self-signed on its own host.
        node = {"env": {"MCP_PUBLIC_ORIGIN": "https://mcp.vana.org"}}
        text = rf.render_compose(
            (COMPOSE_DIR / "docker-compose.fleet-controller.yml").read_text(),
            IMAGES, GIT_REF, SPKI, "dstack-pha-prod9.phala.network",
            rf.mcp_domain(node),
        )

        self.assertIn("- DOMAIN=mcp.vana.org", text)
        self.assertNotIn("mcp-dev", text)

    def test_the_worker_overlay_is_templated_too(self):
        # #311 fixed only the controller; this file kept both prod5 literals.
        text = (COMPOSE_DIR / "docker-compose.fleet-worker-source.yml").read_text()

        self.assertNotIn("mcp-dev.vana.org", text)
        self.assertNotIn("prod5", text)

    def test_a_missing_origin_stops_the_render(self):
        with self.assertRaises(SystemExit):
            rf.mcp_domain({"env": {}})

    def test_a_junk_origin_is_refused(self):
        with self.assertRaises(SystemExit):
            rf.mcp_domain({"env": {"MCP_PUBLIC_ORIGIN": "https://not a host/"}})

    def test_gateway_domain_is_not_mistaken_for_domain(self):
        # "DOMAIN=" is a substring of "GATEWAY_DOMAIN="; the singleton fence
        # must compare whole entries or every valid compose trips it.
        rf.assert_compose(
            "t.yml", rendered("docker-compose.fleet-controller.yml"),
            IMAGES, GIT_REF, SPKI, "controller",
        )


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


class ManifestFencing(unittest.TestCase):
    def test_a_provisioned_manifest_passes(self):
        rf.assert_manifest(json.loads(MANIFEST.read_text()))

    def test_the_mainnet_template_cannot_render(self):
        # It ships with placeholder ids: rendering it would sign a config no
        # enclave can authenticate, so it must fail before any draft is built.
        with self.assertRaises(SystemExit):
            rf.assert_manifest(json.loads(TEMPLATE.read_text()))

    def test_it_names_every_unresolved_field(self):
        manifest = json.loads(MANIFEST.read_text())
        manifest["nodes"]["controller"]["appId"] = "REPLACE_WITH_APP_ID"
        manifest["nodes"]["controller"]["measured"]["rtmrs"][1] = "REPLACE_WITH_RTMR1"

        with self.assertRaises(SystemExit) as raised:
            rf.assert_manifest(manifest)

        self.assertIn("nodes.controller.appId", str(raised.exception))
        self.assertIn("nodes.controller.measured.rtmrs[1]", str(raised.exception))


class ManifestTrustDomain(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(MANIFEST.read_text())

    def test_a_placeholder_key_is_caught(self):
        nodes = self.manifest["nodes"]
        nodes["REPLACE_WITH_WORKER_NAME"] = nodes.pop("worker-1")

        with self.assertRaises(SystemExit) as raised:
            rf.assert_manifest(self.manifest)

        self.assertIn("nodes.REPLACE_WITH_WORKER_NAME", str(raised.exception))

    def test_a_mixed_chain_manifest_is_refused(self):
        self.manifest["nodes"]["worker-1"]["env"]["CHAIN_ID"] = "1480"

        with self.assertRaises(SystemExit) as raised:
            rf.assert_manifest(self.manifest)

        self.assertIn("mixes chains", str(raised.exception))

    def test_a_second_kms_root_is_refused(self):
        self.manifest["nodes"]["worker-1"]["measured"]["keyProviderSpki"] = "other"

        with self.assertRaises(SystemExit) as raised:
            rf.assert_manifest(self.manifest)

        self.assertIn("mixes KMS roots", str(raised.exception))

    def test_a_manifest_without_nodes_is_refused(self):
        with self.assertRaises(SystemExit):
            rf.assert_manifest(["not", "a", "manifest"])


class TemplateStillRendersComposes(unittest.TestCase):
    def test_composes_are_written_before_the_fence_trips(self):
        # A new fleet cannot have ids until its CVMs exist, and its CVMs cannot
        # exist until something renders the composes they are deployed from.
        out = pathlib.Path(tempfile.mkdtemp())
        argv = [
            "render-fleet.py",
            "--manifest", str(TEMPLATE),
            "--images-env", str(out / "images.env"),
            "--out", str(out),
            "--compose-dir", str(COMPOSE_DIR),
            "--git-ref", GIT_REF,
        ]
        (out / "images.env").write_text(
            "\n".join("%s=%s" % (k, v) for k, v in IMAGES.items())
            + "\nPS_IMAGE_REF=%s\n" % GIT_REF
        )
        saved = sys.argv
        sys.argv = argv
        try:
            with self.assertRaises(SystemExit) as raised:
                rf.main()
        finally:
            sys.argv = saved

        # gatewayDomain now reaches the controller compose, so a template that
        # has not chosen its node fails at the compose fence instead of the
        # manifest one. Either way: nothing signable is produced.
        self.assertIn("REPLACE_WITH_", str(raised.exception))
        self.assertFalse(list(out.glob("*config.draft.json")))


class ManifestPatching(unittest.TestCase):
    def setUp(self):
        self.text = MANIFEST.read_text()
        self.manifest = json.loads(self.text)
        self.nodes = self.manifest["nodes"]

    def test_no_change_leaves_the_file_untouched(self):
        hashes = {n: v["pinned"]["composeHash"] for n, v in self.nodes.items()}

        self.assertEqual(rf.patch_compose_hashes(self.text, self.nodes, hashes), self.text)

    def test_only_the_changed_hash_moves(self):
        new_hash = "b" * 64
        hashes = {n: v["pinned"]["composeHash"] for n, v in self.nodes.items()}
        hashes["worker-1"] = new_hash

        patched = rf.patch_compose_hashes(self.text, self.nodes, hashes)

        self.assertNotEqual(patched, self.text)
        self.assertIn(new_hash, patched)
        self.assertNotIn(self.nodes["worker-1"]["pinned"]["composeHash"], patched)
        # every other node's pinned hash, and the rest of the file, is untouched
        patched_manifest = json.loads(patched)
        for name in self.nodes:
            if name == "worker-1":
                continue
            self.assertEqual(
                patched_manifest["nodes"][name]["pinned"]["composeHash"],
                self.nodes[name]["pinned"]["composeHash"],
            )

    def test_preserves_key_order_and_indent(self):
        hashes = {n: v["pinned"]["composeHash"] for n, v in self.nodes.items()}
        hashes["controller"] = "c" * 64

        patched = rf.patch_compose_hashes(self.text, self.nodes, hashes)
        old_lines = self.text.splitlines()
        new_lines = patched.splitlines()

        self.assertEqual(len(old_lines), len(new_lines))
        for old_line, new_line in zip(old_lines, new_lines):
            if "composeHash" in old_line and self.nodes["controller"]["pinned"]["composeHash"] in old_line:
                continue
            self.assertEqual(old_line, new_line)

    def test_patches_one_node_of_a_shared_hash(self):
        # worker-2/3/4 boot the same compose, so one hash is pinned three times.
        shared = self.nodes["worker-2"]["pinned"]["composeHash"]
        self.assertEqual(
            [self.nodes[n]["pinned"]["composeHash"] for n in ("worker-3", "worker-4")],
            [shared, shared],
        )

        hashes = {n: v["pinned"]["composeHash"] for n, v in self.nodes.items()}
        hashes["worker-3"] = "e" * 64

        patched = json.loads(rf.patch_compose_hashes(self.text, self.nodes, hashes))

        self.assertEqual(patched["nodes"]["worker-3"]["pinned"]["composeHash"], "e" * 64)
        self.assertEqual(patched["nodes"]["worker-2"]["pinned"]["composeHash"], shared)
        self.assertEqual(patched["nodes"]["worker-4"]["pinned"]["composeHash"], shared)

    def test_patches_every_node_of_a_shared_hash(self):
        rolled = {"worker-2": "a" * 64, "worker-3": "b" * 64, "worker-4": "c" * 64}
        hashes = {n: rolled.get(n, v["pinned"]["composeHash"]) for n, v in self.nodes.items()}

        patched = json.loads(rf.patch_compose_hashes(self.text, self.nodes, hashes))

        for name, new_hash in rolled.items():
            self.assertEqual(patched["nodes"][name]["pinned"]["composeHash"], new_hash)

    def patch_decoy(self, decoy, new_hash="2" * 64):
        text = json.dumps(decoy, indent=2)

        return json.loads(rf.patch_compose_hashes(text, decoy["nodes"], {"worker-1": new_hash}))

    def test_a_nested_decoy_is_not_the_member(self):
        # A `nodes`/`pinned` key deeper in the tree must not be patched in place
        # of the real one, whichever comes first in the file.
        patched = self.patch_decoy(
            {
                "history": {"nodes": {"worker-1": {"pinned": {"composeHash": "0" * 64}}}},
                "nodes": {"worker-1": {"pinned": {"composeHash": "1" * 64}}},
            }
        )

        self.assertEqual(patched["nodes"]["worker-1"]["pinned"]["composeHash"], "2" * 64)
        self.assertEqual(
            patched["history"]["nodes"]["worker-1"]["pinned"]["composeHash"], "0" * 64
        )

    def test_only_the_pin_itself_moves(self):
        patched = self.patch_decoy(
            {
                "nodes": {
                    "worker-1": {
                        "pinned": {
                            "was": {"composeHash": "0" * 64},
                            "composeHash": "1" * 64,
                        }
                    }
                }
            }
        )

        self.assertEqual(patched["nodes"]["worker-1"]["pinned"]["composeHash"], "2" * 64)
        self.assertEqual(patched["nodes"]["worker-1"]["pinned"]["was"]["composeHash"], "0" * 64)

    def test_a_brace_in_a_value_does_not_end_an_object(self):
        # Signed env arrives as JSON inside a string; naive brace counting would
        # close the node early and patch the wrong block.
        patched = self.patch_decoy(
            {
                "nodes": {
                    "worker-1": {
                        "env": {"POLICY": '{"role":"worker"}'},
                        "pinned": {"composeHash": "1" * 64},
                    }
                }
            }
        )

        self.assertEqual(patched["nodes"]["worker-1"]["pinned"]["composeHash"], "2" * 64)

    def test_the_real_manifest_keeps_every_other_byte(self):
        hashes = {n: v["pinned"]["composeHash"] for n, v in self.nodes.items()}
        hashes["worker-4"] = "f" * 64

        patched = rf.patch_compose_hashes(self.text, self.nodes, hashes)

        self.assertEqual(
            json.loads(patched)["nodes"]["worker-4"]["pinned"]["composeHash"], "f" * 64
        )
        self.assertEqual(
            patched.replace("f" * 64, self.nodes["worker-4"]["pinned"]["composeHash"]),
            self.text,
        )


class MemberSpan(unittest.TestCase):
    def span(self, text, key):
        start, end = rf.member_span(text, key, 0, len(text))

        return json.loads(text[start:end])

    def test_reads_a_direct_member(self):
        self.assertEqual(self.span('{"a": {"b": 1}, "c": "x"}', "a"), {"b": 1})
        self.assertEqual(self.span('{"a": {"b": 1}, "c": "x"}', "c"), "x")

    def test_a_string_value_is_not_a_key(self):
        self.assertEqual(self.span('{"a": "b", "b": {"real": 1}}', "b"), {"real": 1})

    def test_an_array_value_is_not_the_object(self):
        # `"pinned": [{...}]` must fail closed, not hand back the first element.
        with self.assertRaises(SystemExit):
            rf.member_span('{"pinned": [{"composeHash": "0"}]}', "pinned", 0, 33)

    def test_an_escaped_quote_does_not_end_a_value(self):
        self.assertEqual(self.span('{"a": "say \\"b\\": {}", "b": {"real": 1}}', "b"), {"real": 1})


class StageGuards(unittest.TestCase):
    """Driven through stage_all, so the guard's PLACEMENT is under test too."""

    def setUp(self):
        self.live = {"c-uuid": "c-live", "w-uuid": "w-live"}
        self.nodes = {
            "controller": self.node("controller", "c-uuid", "c-live"),
            "worker-1": self.node("worker", "w-uuid", "w-live"),
        }
        self.staged = []
        self.quiet = contextlib.redirect_stderr(io.StringIO())
        self.quiet.__enter__()
        rf.HARVEST.read_attestation = lambda uuid: {"instanceId": self.live[uuid]}
        rf.HARVEST.measured_identity = lambda a, app: a
        rf.stage_node = lambda name, node, path, out: self.staged.append(name) or ("d" * 64)

    def tearDown(self):
        self.quiet.__exit__(None, None, None)
        rf.HARVEST, rf.stage_node = rf.load_harvester(), STAGE_NODE

    def node(self, role, uuid, instance_id):
        return {
            "role": role,
            "uuid": uuid,
            "appId": "shared-app",
            "pinned": {"instanceId": instance_id, "composeHash": "a" * 64},
        }

    def test_stages_every_node_when_the_pins_are_current(self):
        self.assertEqual(rf.stage_all(self.nodes, pathlib.Path(".")).keys(), self.nodes.keys())
        self.assertEqual(self.staged, ["controller", "worker-1"])

    def test_a_stale_worker_pin_stages_nothing(self):
        # The controller is staged first, so a late failure would already have
        # restarted it: the fleet must be checked before anything is applied.
        self.live["w-uuid"] = "w-replaced"

        with self.assertRaises(SystemExit):
            rf.stage_all(self.nodes, pathlib.Path("."))

        self.assertEqual(self.staged, [])

    def test_two_nodes_resolving_to_one_cvm_stage_nothing(self):
        # Replicas share an app id, so only the attested instance tells them
        # apart; both entries answering alike means a uuid resolved wrong.
        self.live["w-uuid"] = "c-live"
        self.nodes["worker-1"]["pinned"]["instanceId"] = "c-live"

        with self.assertRaises(SystemExit):
            rf.stage_all(self.nodes, pathlib.Path("."))

        self.assertEqual(self.staged, [])


if __name__ == "__main__":
    unittest.main()
