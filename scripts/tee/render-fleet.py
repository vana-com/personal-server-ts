#!/usr/bin/env python3
"""Render a fleet's measured composes and its unsigned signed-config drafts.

The fleet manifest (deploy/dstack/fleets/<fleet>.json) carries ids, measured
pins and non-secret env only. Secrets are never rendered: a draft names its
keychain items in `secretRefs`, and sign-fleet.cjs fills them in at signing
time.

  render-fleet.py --manifest deploy/dstack/fleets/preview-prod5.json \
      --images-env ci-docker-<head7>/images.env --out rendered/ [--stage]

`--stage` applies each rendered compose to its CVM with a fail-closed dummy
env, then reads the real dstack `compose_hash` back from the CVM. That hash is
NOT the compose file's sha256, and a byte-identical compose can hash
differently on a different node, so drafts are only ever pinned to a read-back
value. The controller is staged first, so its new hash is available for every
worker's reciprocal pin.
"""

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time

# Every measured literal the composes carry as a REPLACE_WITH_ marker.
IMAGE_MARKERS = {
    "REPLACE_WITH_REVIEWED_AGENT_IMAGE_DIGEST": "AGENT_IMAGE",
    "REPLACE_WITH_REVIEWED_RUNTIME_IMAGE_DIGEST": "RUNTIME_IMAGE",
    "REPLACE_WITH_REVIEWED_PS_IMAGE_DIGEST": "PS_IMAGE",
}
GIT_REF_MARKER = "REPLACE_WITH_REVIEWED_40_HEX_COMMIT"
SPKI_MARKER = "REPLACE_WITH_OPERATOR_ED25519_SPKI_BASE64"
MARKER_PREFIX = "REPLACE_WITH_"

# The one service whose environment the signed bundle reaches.
ROLE_SERVICE = {"controller": "controller", "worker": "agent"}
SIGNED_CONFIG_ENV = "FLEET_SIGNED_CONFIG"
PUBLIC_KEY_ENV = "FLEET_CONFIG_PUBLIC_KEY"
ALLOWED_ENVS = [SIGNED_CONFIG_ENV]

CONFIG_PURPOSE = "vana.fleet.security-config"
CONFIG_VERSION = 1
# The enclave parses these as compact JSON; keep the bytes it was signed with.
COMPACT = (",", ":")
IMAGE_ENV_KEY = "PS_IMAGE"

HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
IMAGE_DIGEST = re.compile(r"^[\w./-]+(?::[\w.-]+)?@sha256:[0-9a-f]{64}$")
IMAGE_LINE = re.compile(r"^\s+image:\s*(.+?)\s*$")
# `$${VAR}` is compose-escaped and stays inside the guest; a bare `${VAR}` is
# interpolated from unmeasured outer env before the compose is measured.
OUTER_INTERPOLATION = re.compile(r"(?<!\$)\$\{")
TOP_LEVEL_KEY = re.compile(r"^([A-Za-z_][A-Za-z0-9_.-]*):")
CHILD_KEY = re.compile(r"^ {2}([^\s:]+):")

PHALA_TIMEOUT_SECONDS = 600
SETTLE_POLL_SECONDS = 15
SETTLE_TIMEOUT_SECONDS = 20 * 60
# An invalid bundle makes the first boot fail closed: no listener opens until
# the real signed config arrives through `phala envs update`.
DUMMY_ENV_LINE = "FLEET_SIGNED_CONFIG={}\n"
PRIVATE_MODE = 0o600

RECEIPT_NAME = "render-receipt.json"
HASH_NOTE = (
    "composeFileSha256 is the rendered file's digest, NOT the dstack "
    "compose_hash. Pin drafts only to a hash read back from a staged CVM."
)


def utc_now():
    """The verifier rejects issuedAt beyond now + 60 s, so stamp this second."""
    stamp = datetime.datetime.now(datetime.timezone.utc)

    return stamp.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def sha256_text(text):
    return hashlib.sha256(text.encode()).hexdigest()


def patch_compose_hashes(text, nodes, hashes):
    """Rewrite only the composeHash values that changed, byte-for-byte
    everywhere else - so an unrelated array or key order in the manifest is
    never reflowed by re-serialising the whole file."""
    for name, node in nodes.items():
        old = node["pinned"]["composeHash"]
        new = hashes[name]
        if old == new:
            continue

        pattern = re.compile(r'("composeHash"\s*:\s*")%s(")' % re.escape(old))
        if len(pattern.findall(text)) != 1:
            raise SystemExit(
                "%s: composeHash %s must appear exactly once to patch safely" % (name, old)
            )

        text = pattern.sub(lambda m: m.group(1) + new + m.group(2), text, count=1)

    return text


def read_images(path):
    """Read a CI images.env into {AGENT_IMAGE: <digest>, ...}."""
    pairs = [line.split("=", 1) for line in path.read_text().split()]

    return dict(pairs)


def split_sections(text):
    """Split a compose into its leading comments and top-level sections.

    Returns (prefix_lines, [(key, body_lines)]). Only the repo's own fleet
    composes are merged, and those carry top-level keys with two-space
    children, so a text splice keeps the reviewed bytes intact where a YAML
    round-trip would rewrite them.
    """
    prefix, sections = [], []
    for line in text.splitlines():
        match = TOP_LEVEL_KEY.match(line)
        if match:
            sections.append((match.group(1), [line]))
            continue

        if not sections:
            prefix.append(line)
            continue

        sections[-1][1].append(line)

    return prefix, sections


def merge_compose(base_text, overlay_text):
    """Splice an overlay compose's sections into the base compose."""
    prefix, base = split_sections(base_text)
    _, overlay = split_sections(overlay_text)
    merged = {key: list(body) for key, body in base}
    order = [key for key, _ in base]

    for key, body in overlay:
        if key not in merged:
            merged[key] = [body[0]]
            order.append(key)

        taken = {CHILD_KEY.match(l).group(1) for l in merged[key] if CHILD_KEY.match(l)}
        for line in body[1:]:
            child = CHILD_KEY.match(line)
            if child and child.group(1) in taken:
                raise SystemExit("Overlay redefines %s.%s" % (key, child.group(1)))

            merged[key].append(line)

    lines = list(prefix)
    for key in order:
        lines.extend(merged[key])

    return "\n".join(lines).rstrip("\n") + "\n"


def render_compose(text, images, git_ref, spki):
    """Replace every REPLACE_WITH_ marker with its reviewed literal."""
    for marker, key in IMAGE_MARKERS.items():
        text = text.replace(marker, images[key])

    return text.replace(GIT_REF_MARKER, git_ref).replace(SPKI_MARKER, spki)


def service_env(text, service):
    """Read one service's `environment:` list out of a rendered compose."""
    _, sections = split_sections(text)
    body = next((b for k, b in sections if k == "services"), [])
    inside, values = False, None

    for line in body[1:]:
        if re.match(r"^ {2}\S", line):
            inside = line.strip().rstrip(":") == service
            continue

        if inside and line.strip() == "environment:":
            values = []
            continue

        if values is None or not inside:
            continue

        if line.startswith("      - "):
            values.append(line[len("      - ") :].strip())
            continue

        if line.strip():
            break

    return values


def assert_compose(name, text, images, git_ref, spki, service):
    """Fence a rendered compose before it is ever staged or measured."""
    # The composes document their own markers in comments; only code counts.
    for line in text.splitlines():
        if not line.lstrip().startswith("#") and MARKER_PREFIX in line:
            raise SystemExit("%s: unresolved marker: %s" % (name, line.strip()))

    if OUTER_INTERPOLATION.search(text):
        raise SystemExit("%s: outer ${VAR} interpolation in a measured field" % name)

    if "GIT_REF='%s'" % git_ref not in text:
        raise SystemExit("%s: GIT_REF literal missing" % name)

    for line in text.splitlines():
        match = IMAGE_LINE.match(line)
        if match and not IMAGE_DIGEST.match(match.group(1).strip('"')):
            raise SystemExit("%s: image is not digest-pinned: %s" % (name, match.group(1)))

    if images["AGENT_IMAGE"] not in text:
        raise SystemExit("%s: AGENT_IMAGE literal missing" % name)

    expected = ["%s=%s" % (PUBLIC_KEY_ENV, spki), SIGNED_CONFIG_ENV]
    if service_env(text, service) != expected:
        raise SystemExit("%s: %s environment is not the signed-config pair" % (name, service))


def measured_policy(node, role, compose_hash):
    """The identity + measurement block a peer pins another node by."""
    measured = node["measured"]

    return {
        "identity": {
            "role": role,
            "nodeId": node["nodeId"],
            "appId": node["appId"],
            "instanceId": node["pinned"]["instanceId"],
            "composeHash": compose_hash,
        },
        "measurementMode": measured["measurementMode"],
        "mrTd": measured["mrTd"],
        "rtmrs": measured["rtmrs"],
        "osImageHash": measured["osImageHash"],
        "keyProviderSpki": measured["keyProviderSpki"],
    }


def node_url(manifest, node, port_key):
    """A dstack Gateway URL for one of the node's measured ports."""
    port = node["env"][port_key]

    return "https://%s-%s.%s" % (node["pinned"]["instanceId"], port, manifest["gatewayDomain"])


def worker_entries(manifest, nodes, hashes):
    """The controller's signed worker directory, in manifest order."""
    entries = []
    for name, node in nodes.items():
        if node["role"] != "worker":
            continue

        entries.append(
            {
                "url": node_url(manifest, node, "FLEET_PEER_PORT"),
                "capacity": node["capacity"],
                "policy": measured_policy(node, "worker", hashes[name]),
            }
        )

    return entries


def controller_pins(nodes, hashes, staged):
    """Staged reciprocal pins: the controller hash now, and the one next.

    A worker signed with both admits the controller on either side of a roll,
    which is what keeps the roll free of a hash cycle.
    """
    name, node = controller_of(nodes)
    ordered, seen = [], set()
    # Extra pins first, then the manifest's current hash, then the staged one.
    for compose_hash in list(staged) + [node["pinned"]["composeHash"], hashes[name]]:
        if compose_hash in seen:
            continue

        seen.add(compose_hash)
        ordered.append(measured_policy(node, "controller", compose_hash))

    return ordered


def controller_of(nodes):
    for name, node in nodes.items():
        if node["role"] == "controller":
            return name, node

    raise SystemExit("Manifest has no controller node")


def draft_env(manifest, nodes, name, images, hashes, staged):
    """The signed, measured env for one node - no secrets, no interpolation."""
    node = nodes[name]
    env = dict(node["env"])

    if IMAGE_ENV_KEY in env:
        raise SystemExit("%s: %s comes from images.env, not the manifest" % (name, IMAGE_ENV_KEY))

    if node["role"] == "worker":
        env[IMAGE_ENV_KEY] = images[IMAGE_ENV_KEY]
        pins = controller_pins(nodes, hashes, staged)
        env["FLEET_PEER_POLICIES"] = json.dumps(pins, separators=COMPACT)
    else:
        entries = worker_entries(manifest, nodes, hashes)
        env["FLEET_WORKERS_JSON"] = json.dumps(entries, separators=COMPACT)

    for key, value in env.items():
        if not isinstance(value, str):
            raise SystemExit("%s: env %s is not a string" % (name, key))

        if OUTER_INTERPOLATION.search(value):
            raise SystemExit("%s: env %s carries ${VAR}" % (name, key))

    return env


def build_draft(manifest, nodes, name, images, hashes, staged, issued_at):
    node = nodes[name]

    return {
        "version": CONFIG_VERSION,
        "purpose": CONFIG_PURPOSE,
        "role": node["role"],
        "appId": node["appId"],
        "instanceId": node["pinned"]["instanceId"],
        "nodeId": node["nodeId"],
        "issuedAt": issued_at,
        # A fleet config never expires on its own; a roll replaces it.
        "expiresAt": None,
        "env": draft_env(manifest, nodes, name, images, hashes, staged),
        "secretRefs": node["secretRefs"],
    }


def phala(args):
    """One read-only Phala CLI call, decoded as JSON."""
    out = subprocess.check_output(
        ["phala"] + args, text=True, timeout=PHALA_TIMEOUT_SECONDS
    )

    return json.loads(out)


def stage_node(name, node, compose_path, out_dir):
    """Apply one rendered compose to its CVM and read the real hash back."""
    before = phala(["api", "/cvms/" + node["uuid"], "--json"])
    if before["app_id"] != node["appId"]:
        raise SystemExit("%s: staged CVM carries app id %s" % (name, before["app_id"]))

    if before["resource"]["instance_type"] != node["instanceType"]:
        raise SystemExit("%s: instance type moved to %s" % (name, before["resource"]["instance_type"]))

    body = compose_path.read_text()
    handle, env_path = tempfile.mkstemp(prefix="fleet-dummy-env-")
    os.chmod(env_path, PRIVATE_MODE)
    try:
        with os.fdopen(handle, "w") as env_file:
            env_file.write(DUMMY_ENV_LINE)

        result = subprocess.run(
            ["phala", "deploy", "--cvm-id", node["uuid"], "--no-dev-os",
             "-c", str(compose_path), "-e", env_path, "--json"],
            capture_output=True,
            text=True,
            timeout=PHALA_TIMEOUT_SECONDS,
        )
    finally:
        os.unlink(env_path)

    # The CLI echoes the env it pushed; keep that response out of evidence.
    log = out_dir / ("%s-stage-response-private.txt" % name)
    log.write_text((result.stdout or "") + (result.stderr or ""))
    log.chmod(PRIVATE_MODE)
    if result.returncode:
        raise SystemExit("%s: phala deploy exit %d; see %s" % (name, result.returncode, log))

    after = phala(["api", "/cvms/" + node["uuid"], "--json"])
    (out_dir / ("%s-staged-cvm.json" % name)).write_text(json.dumps(after, indent=2) + "\n")
    if after["compose_file"]["allowed_envs"] != ALLOWED_ENVS:
        raise SystemExit("%s: allowed_envs is %s" % (name, after["compose_file"]["allowed_envs"]))

    if after["compose_file"]["docker_compose_file"] != body:
        raise SystemExit("%s: staged compose differs from the rendered file" % name)

    if not HEX64.match(after["compose_hash"]):
        raise SystemExit("%s: unreadable compose_hash" % name)

    return after["compose_hash"]


def settle(nodes):
    """Wait for every staged CVM to report `running` before anything signs."""
    deadline = time.time() + SETTLE_TIMEOUT_SECONDS
    while time.time() < deadline:
        states = {n: phala(["api", "/cvms/" + v["uuid"], "--json"])["status"] for n, v in nodes.items()}
        print(utc_now(), json.dumps(states), file=sys.stderr, flush=True)
        if all(state == "running" for state in states.values()):
            return states

        time.sleep(SETTLE_POLL_SECONDS)

    raise SystemExit("CVMs did not settle to running within the budget")


def render_composes(manifest, nodes, args, images, out_dir):
    """Render each distinct compose once; nodes may share one file."""
    compose_dir = args.compose_dir
    rendered = {}
    for name, node in nodes.items():
        target = node.get("composeOut", "%s-compose.yml" % name)
        if target in rendered:
            continue

        text = (compose_dir / node["compose"]).read_text()
        for overlay in node.get("composeOverlays", []):
            text = merge_compose(text, (compose_dir / overlay).read_text())

        text = render_compose(text, images, args.git_ref, manifest["operatorPublicKeySpkiBase64"])
        assert_compose(
            target, text, images, args.git_ref,
            manifest["operatorPublicKeySpkiBase64"], ROLE_SERVICE[node["role"]],
        )
        (out_dir / target).write_text(text)
        rendered[target] = sha256_text(text)

    return rendered


def stage_all(nodes, out_dir):
    """Stage the controller first, so workers can pin its new hash."""
    controller, _ = controller_of(nodes)
    order = [controller] + [n for n in nodes if n != controller]
    staged = {}
    for name in order:
        node = nodes[name]
        target = node.get("composeOut", "%s-compose.yml" % name)
        staged[name] = stage_node(name, node, out_dir / target, out_dir)
        print("staged %s %s" % (name, staged[name]), file=sys.stderr)

    return staged


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manifest", required=True, type=pathlib.Path)
    parser.add_argument("--images-env", required=True, type=pathlib.Path)
    parser.add_argument("--out", required=True, type=pathlib.Path)
    parser.add_argument("--compose-dir", type=pathlib.Path, default=pathlib.Path("deploy/dstack"))
    parser.add_argument("--git-ref", help="40-hex provenance commit; defaults to PS_IMAGE_REF")
    parser.add_argument(
        "--controller-hash",
        action="append",
        default=[],
        metavar="HEX64",
        help="extra controller compose hash to keep in every worker's reciprocal pin",
    )
    parser.add_argument("--stage", action="store_true", help="apply each compose and read its real hash back")
    parser.add_argument("--settle", action="store_true", help="with --stage, wait for every CVM to run")
    parser.add_argument("--write-manifest", action="store_true", help="persist staged hashes into the manifest")

    return parser.parse_args()


def main():
    args = parse_args()
    manifest_text = args.manifest.read_text()
    manifest = json.loads(manifest_text)
    nodes = manifest["nodes"]
    images = read_images(args.images_env)
    args.git_ref = args.git_ref or images.get("PS_IMAGE_REF")

    if not args.git_ref or not HEX40.match(args.git_ref):
        raise SystemExit("A 40-hex --git-ref is required")

    if "PS_IMAGE_REF" in images and images["PS_IMAGE_REF"] != args.git_ref:
        raise SystemExit("--git-ref does not match the image's PS_IMAGE_REF")

    for key in IMAGE_MARKERS.values():
        if not IMAGE_DIGEST.match(images[key]):
            raise SystemExit("%s is not digest-pinned: %s" % (key, images[key]))

    for extra in args.controller_hash:
        if not HEX64.match(extra):
            raise SystemExit("--controller-hash must be 64 hex: %s" % extra)

    args.out.mkdir(parents=True, exist_ok=True)
    composes = render_composes(manifest, nodes, args, images, args.out)

    hashes = {name: node["pinned"]["composeHash"] for name, node in nodes.items()}
    if args.stage:
        hashes = stage_all(nodes, args.out)

    if args.stage and args.settle:
        settle(nodes)

    for name, compose_hash in hashes.items():
        if not HEX64.match(compose_hash):
            raise SystemExit("%s: compose hash is not 64 hex" % name)

    issued_at = utc_now()
    drafts = {}
    for name in nodes:
        draft = build_draft(manifest, nodes, name, images, hashes, args.controller_hash, issued_at)
        target = nodes[name].get("draft", "%s-config.draft.json" % name)
        (args.out / target).write_text(json.dumps(draft, indent=2) + "\n")
        drafts[target] = sha256_text(json.dumps(draft, indent=2) + "\n")

    receipt = {
        "renderedAt": issued_at,
        "fleet": manifest["fleet"],
        "gitRef": args.git_ref,
        "images": {key: images[key] for key in IMAGE_MARKERS.values()},
        "composeFileSha256": composes,
        "draftSha256": drafts,
        "composeHashes": hashes,
        "staged": bool(args.stage),
        "note": HASH_NOTE,
    }
    (args.out / RECEIPT_NAME).write_text(json.dumps(receipt, indent=2) + "\n")

    if args.write_manifest:
        # Patch in place: keeps the input's key order, indent and array
        # layout untouched outside the hashes that actually changed.
        args.manifest.write_text(patch_compose_hashes(manifest_text, nodes, hashes))

    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
