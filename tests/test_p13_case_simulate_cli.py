import tempfile
import unittest
from pathlib import Path

import ieimctl


class TestP13CaseSimulateCLI(unittest.TestCase):
    def test_case_simulate_servicenow(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            rc = ieimctl.main(
                [
                    "case",
                    "simulate",
                    "--adapter",
                    "servicenow",
                    "--samples",
                    "data/samples",
                    "--out-dir",
                    str(out_dir),
                    "--config",
                    "configs/dev.yaml",
                ]
            )
            self.assertEqual(rc, 0)
            runs = list(out_dir.glob("run_*"))
            self.assertEqual(len(runs), 1)
            self.assertTrue((runs[0] / "case").exists())


if __name__ == "__main__":
    unittest.main()

