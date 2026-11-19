"""Export an APNER001 micro person model as an integer ONNX sequence tagger."""

import argparse
import hashlib
from pathlib import Path
import struct

import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper


def read_model(path):
    """Validate the bounded source model and unpack its signed integer weights."""
    with path.open("rb") as source:
        data = source.read(16 + 8192 * 6 + 1)
    if len(data) < 16 or data[:8] != b"APNER001":
        raise ValueError("invalid-person-model")
    buckets, version = struct.unpack("<ii", data[8:16])
    if not 256 <= buckets <= 8192 or buckets & (buckets - 1) or version != 1:
        raise ValueError("invalid-person-model")
    if len(data) != 16 + buckets * 6:
        raise ValueError("invalid-person-model")
    weights = np.frombuffer(data, dtype="<i2", offset=16).astype(np.int32).reshape(buckets, 3)
    return weights, hashlib.sha256(data).hexdigest()


def build_graph(weights, source_sha):
    """Score every previous-label view, then decode one left-to-right BIO sequence."""
    # The state carries the predicted label, exactly as in MicroPersonModel.Find.
    body = helper.make_graph(
        [
            helper.make_node("Gather", ["candidate_scores", "previous_label"], ["step_scores"], axis=0),
            helper.make_node("ArgMax", ["step_scores"], ["new_label"], axis=0, keepdims=0, select_last_index=0),
            helper.make_node("Identity", ["new_label"], ["emitted_label"]),
        ],
        "greedy_bio",
        [
            helper.make_tensor_value_info("previous_label", TensorProto.INT64, []),
            helper.make_tensor_value_info("candidate_scores", TensorProto.INT32, [3, 3]),
        ],
        [
            helper.make_tensor_value_info("new_label", TensorProto.INT64, []),
            helper.make_tensor_value_info("emitted_label", TensorProto.INT64, []),
        ],
    )
    graph = helper.make_graph(
        [
            helper.make_node("Gather", ["weights", "features"], ["feature_scores"], axis=0),
            helper.make_node("ReduceSum", ["feature_scores", "feature_axis"], ["scores"], keepdims=0),
            helper.make_node("Scan", ["initial_label", "scores"], ["final_label", "labels"],
                             body=body, num_scan_inputs=1),
        ],
        "agprivacy_person_v1",
        [helper.make_tensor_value_info("features", TensorProto.INT64, ["tokens", 3, 12])],
        [helper.make_tensor_value_info("labels", TensorProto.INT64, ["tokens"])],
        initializer=[
            numpy_helper.from_array(weights, "weights"),
            numpy_helper.from_array(np.array([2], dtype=np.int64), "feature_axis"),
            numpy_helper.from_array(np.array(0, dtype=np.int64), "initial_label"),
        ],
    )
    model = helper.make_model(
        graph, producer_name="ag-privacy", producer_version="0.2.0",
        opset_imports=[helper.make_opsetid("", 17)], ir_version=9,
    )
    helper.set_model_props(model, {
        "agprivacy.format": "person-perceptron-v1",
        "agprivacy.buckets": str(weights.shape[0]),
        "agprivacy.source_sha256": source_sha,
    })
    onnx.checker.check_model(model, full_check=True)
    return model


def export(source, destination):
    """Write one self-contained graph, including weights and feature-contract metadata."""
    weights, source_sha = read_model(source)
    model = build_graph(weights, source_sha)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(model.SerializeToString())


def main():
    """Parse local paths, export a graph and emit a fixed status message."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    export(args.source, args.destination)
    print("Exported validated ONNX person model.")


if __name__ == "__main__":
    main()
