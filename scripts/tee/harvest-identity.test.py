#!/usr/bin/env python3
"""Unit tests for harvest-identity.py: `python3 harvest-identity.test.py`.

Nothing here calls phala; the CLI read is the one thing stubbed out.
"""

import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
import unittest.mock

HERE = pathlib.Path(__file__).resolve().parent

# Two worker replicas of one app: the case `phala cvms list` collapses.
SHARED_APP_ID = "ec9a39de98c760e1ded9f1e97016dc5f0e357cf2"
SPKI = "3059301306072a8648ce3d0201"
NODES = {
    "worker-1": {"uuid": "87c32ca4", "appId": SHARED_APP_ID},
    "worker-2": {"uuid": "1a5acf08", "appId": SHARED_APP_ID},
}
INSTANCES = {"87c32ca4": "1ac22335a2da", "1a5acf08": "eeea1588a1f5"}


def load_module():
    spec = importlib.util.spec_from_file_location("harvest_identity", HERE / "harvest-identity.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


hi = load_module()


def attestation(app_id, instance_id):
    """One CVM's quote, reduced to the IMR-3 events the harvester reads."""
    events = {
        "app-id": app_id,
        "instance-id": instance_id,
        "compose-hash": "c" * 64,
        "os-image-hash": "o" * 64,
        "mr-kms": "k" * 64,
        "key-provider": json.dumps({"id": SPKI}).encode().hex(),
    }

    return {
        "tcb_info": {
            "mrtd": "m" * 96,
            "rtmr0": "0" * 96,
            "rtmr1": "1" * 96,
            "rtmr2": "2" * 96,
            "event_log": [
                {"imr": 0, "event": "app-id", "event_payload": "ignored"},
                *[{"imr": 3, "event": e, "event_payload": p} for e, p in events.items()],
            ],
        }
    }


class MeasuredIdentity(unittest.TestCase):
    def test_reduces_the_event_log(self):
        identity = hi.measured_identity(attestation(SHARED_APP_ID, "i-1"), SHARED_APP_ID)

        self.assertEqual(identity["instanceId"], "i-1")
        self.assertEqual(identity["keyProviderSpki"], SPKI)
        self.assertEqual(identity["measurementMode"], hi.MEASUREMENT_MODE)
        self.assertEqual(identity["rtmrs"], ["0" * 96, "1" * 96, "2" * 96])

    def test_rejects_another_app(self):
        with self.assertRaises(SystemExit):
            hi.measured_identity(attestation("other", "i-1"), SHARED_APP_ID)


class SharedAppId(unittest.TestCase):
    """Two CVMs under one app id: only the instance id tells them apart.

    Driven through `main()` so the guard is under test where it runs, not only
    where it is defined.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.nodes_path = pathlib.Path(self.temp.name) / "nodes.json"
        self.read_attestation = hi.read_attestation
        self.addCleanup(setattr, hi, "read_attestation", self.read_attestation)

    def harvest(self, by_uuid, nodes=NODES):
        self.nodes_path.write_text(json.dumps(nodes))
        hi.read_attestation = lambda uuid: attestation(SHARED_APP_ID, by_uuid[uuid])
        out = io.StringIO()
        argv = ["harvest-identity.py", "--nodes", str(self.nodes_path)]

        with unittest.mock.patch.object(sys, "argv", argv):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                hi.main()

        return json.loads(out.getvalue())

    def test_each_replica_keeps_its_own_instance(self):
        harvested = self.harvest(INSTANCES)

        self.assertEqual(harvested["worker-1"]["instanceId"], INSTANCES["87c32ca4"])
        self.assertEqual(harvested["worker-2"]["instanceId"], INSTANCES["1a5acf08"])

    def test_refuses_one_instance_answering_for_two_nodes(self):
        # A uuid that resolved to the wrong replica: the app-id echo still
        # passes, so without the instance check worker-2 would pin worker-1's.
        both = dict.fromkeys(INSTANCES, INSTANCES["87c32ca4"])

        with self.assertRaises(SystemExit):
            self.harvest(both)

    def test_refuses_an_instance_the_caller_did_not_expect(self):
        nodes = {"worker-1": {**NODES["worker-1"], "instanceId": "repinned-elsewhere"}}

        with self.assertRaises(SystemExit):
            self.harvest(INSTANCES, nodes)

    def test_accepts_the_expected_instance(self):
        pinned = INSTANCES["87c32ca4"]
        nodes = {"worker-1": {**NODES["worker-1"], "instanceId": pinned}}

        self.assertEqual(self.harvest(INSTANCES, nodes)["worker-1"]["instanceId"], pinned)


if __name__ == "__main__":
    unittest.main()
