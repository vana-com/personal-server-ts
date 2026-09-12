#!/usr/bin/env python3
"""Harvest each CVM's measured identity from its attestation event log.

`phala api /cvms/<uuid>` leaves `instance_id` null forever, so the instance id,
compose hash, mr-kms, key-provider SPKI and MRTD/RTMRs all come from the quote
instead. Those values are the inputs to a signed fleet config draft.

  harvest-identity.py --nodes nodes.json [--save-attestations DIR] > identities.json

`nodes.json` maps a role name to at least `{"uuid": ..., "appId": ...}`; every
other key on the entry is copied through to the output untouched.
"""

import argparse
import binascii
import json
import pathlib
import subprocess
import sys

# dstack records the launch measurements as IMR 3 event-log entries.
MEASURED_IMR = 3
MEASUREMENT_MODE = "dstack-0.5.9-events"
PHALA_TIMEOUT_SECONDS = 60


def read_attestation(uuid):
    """Pull one CVM's raw attestation document through the Phala CLI."""
    out = subprocess.check_output(
        ["phala", "api", "/cvms/%s/attestation" % uuid, "--json"],
        text=True,
        timeout=PHALA_TIMEOUT_SECONDS,
    )

    return json.loads(out)


def measured_identity(attestation, expected_app_id):
    """Reduce one attestation to the fields a signed config draft needs."""
    tcb = attestation["tcb_info"]
    events = {
        e["event"]: e.get("event_payload", "")
        for e in tcb["event_log"]
        if e["imr"] == MEASURED_IMR
    }

    # A mismatch means the CLI answered about a different CVM than we staged.
    if events["app-id"] != expected_app_id:
        raise SystemExit("app-id %s does not match %s" % (events["app-id"], expected_app_id))

    # The key-provider payload is hex-encoded JSON; its `id` is the KMS SPKI.
    key_provider = json.loads(binascii.unhexlify(events["key-provider"]))

    return {
        "measurementMode": MEASUREMENT_MODE,
        "instanceId": events["instance-id"],
        "composeHash": events["compose-hash"],
        "osImageHash": events["os-image-hash"],
        "mrKms": events["mr-kms"],
        "keyProviderSpki": key_provider["id"],
        "mrTd": tcb["mrtd"],
        "rtmrs": [tcb["rtmr0"], tcb["rtmr1"], tcb["rtmr2"]],
    }


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nodes", required=True, type=pathlib.Path)
    parser.add_argument(
        "--save-attestations",
        type=pathlib.Path,
        help="directory to write each raw <name>-attestation.json into",
    )

    return parser.parse_args()


def main():
    args = parse_args()
    nodes = json.loads(args.nodes.read_text())

    if args.save_attestations:
        args.save_attestations.mkdir(parents=True, exist_ok=True)

    identities = {}
    for name, node in nodes.items():
        attestation = read_attestation(node["uuid"])

        if args.save_attestations:
            path = args.save_attestations / ("%s-attestation.json" % name)
            path.write_text(json.dumps(attestation, indent=2) + "\n")

        identities[name] = {**node, **measured_identity(attestation, node["appId"])}
        print(
            "%s %s %s" % (name, identities[name]["instanceId"], identities[name]["composeHash"]),
            file=sys.stderr,
        )

    print(json.dumps(identities, indent=2))


if __name__ == "__main__":
    main()
