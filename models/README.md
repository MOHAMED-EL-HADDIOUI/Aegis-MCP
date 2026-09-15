# Models (text classifier weights)

No weights are shipped in this directory, deliberately: the gateway must be
secure out-of-the-box with zero downloads, so the default classifier is the
in-tree heuristic (`HeuristicClassifier` in
`crates/aegis-classifier/src/lib.rs`).

## Providers

| provider | how it is selected | behavior |
|---|---|---|
| `heuristic` (default) | `classifier.provider = "heuristic"` in `aegis.yaml`, or no model configured | regex + tool-prior scoring, `risk_score` in [0,1] |
| `onnx` | `--features onnx` build **plus** a model path wired into `OnnxClassifier::new(Some(path))` | runs the ONNX model, fuses with heuristic via `max` (AI may only escalate, never de-escalate) |
| `disabled` | `classifier.enabled = false` | `RiskAssessment::default()` (zero risk) |

## Expected ONNX model contract

If you train your own model, it must match exactly what `run_onnx_model`
(`crates/aegis-classifier/src/lib.rs`, compiled only with `--features onnx`)
feeds the session:

- **Input**: name `"input"`, shape `[1, 256]`, `float32` — a normalized
  **character-histogram**: `feats[byte] += 1` for every byte of the tool-call
  JSON (`ctx.args.to_string()`), divided by `text.len()`.
- **Output**: name `"output"`, one `float32` **logit**; the code applies
  `sigmoid` to map it into [0,1] and takes `max(model, heuristic)`.

## How to train / export such a model

1. Collect labeled tool-call JSON strings (malicious = 1, benign = 0). The
   corpus in `tests/fixtures/injection_samples.jsonl` is a starting point,
   not a training set.
2. Featurize each sample as the 256-dim normalized byte histogram above.
3. Train any binary classifier (e.g. logistic regression / small MLP in
   scikit-learn or PyTorch) on those vectors.
4. Export to ONNX with input name `"input"` and a single-logit output named
   `"output"` (e.g. `torch.onnx.export(..., input_names=["input"],
   output_names=["output"])`).
5. Drop the `.onnx` file here (e.g. `models/charhist-mlp.onnx`), build with
   `--features onnx` (pulls the `ort` crate, `download-binaries`), and point
   the gateway config at it.

Until a real file exists here, anything claiming otherwise is aspirational:
there is intentionally **no fake `.onnx` checked in**.
