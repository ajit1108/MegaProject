# ============================================================
# tests/evaluate_nlp.py
# Real before/after evaluation of the detection engine on gold data.
#
# Usage (from sensitive-data-detection/):
#   python -m tests.evaluate_nlp --engine legacy  --split dev
#   python -m tests.evaluate_nlp --engine current --split dev
#   python -m tests.evaluate_nlp --engine legacy  --split heldout
#   python -m tests.evaluate_nlp --engine current --split heldout
#
# Writes tests/nlp_eval_<label>.json and prints a human-readable report.
# Nothing is fabricated: every number comes from running the engine.
# ============================================================
import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from tests.nlp_dataset import load_docs, load_heldout_docs, load_natural_docs
from tests.nlp_scorer import evaluate


def _load_engine(name: str):
    if name == "legacy":
        from tests import legacy_engine

        legacy_engine._load_nlp()
        return legacy_engine.detect, bool(legacy_engine._nlp_available)

    from app.services.detection_engine import detect, nlp_is_available

    return detect, nlp_is_available()


def fmt(x: float) -> str:
    return f"{x * 100:5.1f}%"


def print_report(report: dict, label: str) -> None:
    print("=" * 78)
    print(f"NLP EVALUATION — {label}")
    print("=" * 78)
    print(f"Documents: {report['documents']} | Gold spans: {report['gold_spans']} | "
          f"Predicted spans: {report['predicted_spans']} | spaCy available: {report['nlp_available']}")
    print(f"Total time: {report['elapsed_seconds']:.2f}s "
          f"({report['elapsed_seconds'] / max(1, report['documents']):.3f}s/doc)")

    for mode in ("strict", "relaxed"):
        m = report[mode]
        print(f"\n[{mode.upper()} SPAN MATCH]")
        print(f"  Precision {fmt(m['precision'])}  Recall {fmt(m['recall'])}  F1 {fmt(m['f1'])}  "
              f"(TP={m['tp']} FP={m['fp']} FN={m['fn']})")

        print("  Per entity type:")
        for etype in sorted(m["per_type"]):
            s = m["per_type"][etype]
            print(f"    {etype:<22} P={fmt(s['precision'])} R={fmt(s['recall'])} "
                  f"F1={fmt(s['f1'])}  TP={s['tp']:<3} FP={s['fp']:<3} FN={s['fn']}")

    print("\nPer document (strict TP/FP/FN):")
    for d in report["per_document"]:
        print(f"  {d['id']:<24} gold={d['gold']:<2} pred={d['predicted']:<2} "
              f"TP={d['strict']['tp']:<2} FP={d['strict']['fp']:<2} FN={d['strict']['fn']}")

    print("\nSample false positives (strict):")
    for fp in report["strict"]["false_positives"][:15]:
        print(f"  - {fp['entity_type']:<18} {fp['matched_value']!r} "
              f"@[{fp['start']}:{fp['end']}] method={fp['detection_method']}")

    print("\nSample false negatives (strict):")
    for fn in report["strict"]["false_negatives"][:15]:
        print(f"  - {fn['entity_type']:<18} {fn['matched_value']!r} "
              f"@[{fn['start']}:{fn['end']}]")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", choices=["current", "legacy"], default="current")
    parser.add_argument("--split", choices=["dev", "heldout", "natural", "all"], default="dev")
    parser.add_argument("--label", default=None)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    if args.split == "dev":
        docs = load_docs()
    elif args.split == "heldout":
        docs = load_heldout_docs()
    elif args.split == "natural":
        docs = load_natural_docs()
    else:
        docs = load_docs() + load_heldout_docs() + load_natural_docs()

    engine_detect, nlp_available = _load_engine(args.engine)
    label = args.label or f"{args.engine}_{args.split}"

    start = time.perf_counter()
    report = evaluate(docs, engine_detect)
    elapsed = time.perf_counter() - start

    report.update({
        "label": label,
        "engine": args.engine,
        "split": args.split,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "nlp_available": nlp_available,
        "elapsed_seconds": round(elapsed, 4),
    })

    out = Path(args.out) if args.out else Path("tests") / f"nlp_eval_{label}.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print_report(report, label)
    print(f"\nSaved: {out}")


if __name__ == "__main__":
    main()
