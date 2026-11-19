"""Check source-model validation, deterministic export and its public tensor contract."""
from pathlib import Path
import struct
import tempfile
import unittest

import onnx

from export_person import export, read_model


class ExportTests(unittest.TestCase):
    def test_signed_weights_and_deterministic_export(self):
        """Preserve signed short values and embed reproducible metadata."""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "model.bin"
            weights = [-32768, 0, 32767] * 256
            source.write_bytes(b"APNER001" + struct.pack("<ii", 256, 1) + struct.pack("<768h", *weights))
            export(source, root / "first.onnx")
            export(source, root / "second.onnx")
            self.assertEqual((root / "first.onnx").read_bytes(), (root / "second.onnx").read_bytes())
            model = onnx.load(root / "first.onnx")
            table = onnx.numpy_helper.to_array(model.graph.initializer[0])
            self.assertEqual(list(table[0]), [-32768, 0, 32767])
            self.assertEqual(model.graph.input[0].name, "features")
            self.assertEqual(model.graph.output[0].name, "labels")
            self.assertEqual(model.opset_import[0].version, 17)

    def test_invalid_sources(self):
        """Reject malformed signatures, dimensions, versions and truncated or trailing weights."""
        valid = b"APNER001" + struct.pack("<ii", 256, 1) + bytes(256 * 6)
        cases = [
            b"", b"WRONG001" + valid[8:], valid[:-1], valid + b"x",
            b"APNER001" + struct.pack("<ii", 255, 1) + bytes(255 * 6),
            b"APNER001" + struct.pack("<ii", 256, 2) + bytes(256 * 6),
            b"APNER001" + struct.pack("<ii", 16384, 1) + bytes(16384 * 6),
        ]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "invalid.bin"
            for data in cases:
                path.write_bytes(data)
                with self.assertRaises(ValueError):
                    read_model(path)


if __name__ == "__main__":
    unittest.main()
