"""One-command check for gatepost/v1: `python3 -m unittest discover -s test -p 'test_*.py'`.

Needs the openssl CLI (the tamper suite signs with fresh throwaway keys, deleted afterwards).
"""
import json, os, subprocess, sys, tempfile, unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
TOOLS = os.path.join(ROOT, "tools")
DEMO = os.path.join(ROOT, "out", "or_veto_pack_DEMO_KEY")
sys.path.insert(0, TOOLS)
from gp_encoding import row_hash  # noqa: E402

DEMO_KEY = json.load(open(os.path.join(DEMO, "keys.json")))[0]["key_id"]


def verify(*args):
    return subprocess.run([sys.executable, os.path.join(TOOLS, "verify.py"), *args],
                          capture_output=True, text=True).returncode


class GatepostV1(unittest.TestCase):
    def test_vectors_reproduce(self):
        v = json.load(open(os.path.join(ROOT, "test", "vectors.json")))
        for case in v["vectors"]:
            row = {k: val for k, val in case["row"].items() if k != "row_hash"}
            self.assertEqual(row_hash(row, v["columns"]), case["row"]["row_hash"])

    def test_demo_pack_unpinned_is_not_a_pass(self):
        self.assertEqual(verify(DEMO), 5)

    def test_demo_pack_pinned_verifies(self):
        self.assertEqual(verify(DEMO, "--expect-key", DEMO_KEY), 0)

    def test_tamper_suite(self):
        with tempfile.TemporaryDirectory() as d:
            keys = []
            for n in ("A", "B", "X"):
                p = os.path.join(d, n + ".pem")
                subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                                "rsa_keygen_bits:3072", "-out", p], check=True, capture_output=True)
                keys.append(p)
            r = subprocess.run([sys.executable, os.path.join(ROOT, "test", "tamper_suite.py"), DEMO, *keys],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout[-2000:])


if __name__ == "__main__":
    unittest.main()
