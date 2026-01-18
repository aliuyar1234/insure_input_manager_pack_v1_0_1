import tempfile
import unittest
from pathlib import Path

import ieimctl


class TestP13IngestSimulateCLI(unittest.TestCase):
    def test_ingest_simulate_filesystem(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            rc = ieimctl.main(
                [
                    "ingest",
                    "simulate",
                    "--adapter",
                    "filesystem",
                    "--samples",
                    "data/samples",
                    "--out-dir",
                    str(out_dir),
                ]
            )
            self.assertEqual(rc, 0)
            self.assertTrue((out_dir / "emails").exists())
            self.assertGreaterEqual(len(list((out_dir / "emails").glob("*.json"))), 1)
            self.assertTrue((out_dir / "audit").exists())


if __name__ == "__main__":
    unittest.main()

