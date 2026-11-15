# ============================================================
# tests/nlp_scorer.py
# Span-level precision / recall / F1 scorer for the detection engine.
#
# Two matching modes are reported:
#   strict  - predicted (start, end) must exactly equal the gold span
#   relaxed - predicted span must overlap the gold span by >= 50 % of
#             the gold length (same entity family)
#
# Type compatibility only widens a handful of legacy names; it does not
# merge semantically different entities.
# ============================================================

TYPE_FAMILY: dict[str, str] = {
    "PHONE": "PHONE",
    "PHONE_IN": "PHONE",
    "PHONE_GENERIC": "PHONE",
    "MOBILE": "PHONE",

    "PERSON": "PERSON_NAME",
    "PER": "PERSON_NAME",
    "PERSON_NAME": "PERSON_NAME",

    "ORG": "ORGANIZATION",
    "ORG_NAME": "ORGANIZATION",
    "ORGANIZATION": "ORGANIZATION",

    "GEO_POLITICAL": "LOCATION",
    "LOC": "LOCATION",
    "GPE": "LOCATION",
    "LOCATION": "LOCATION",

    "MONEY": "FINANCIAL_VALUE",
    "SALARY": "FINANCIAL_VALUE",
    "FINANCIAL_VALUE": "FINANCIAL_VALUE",

    "DATE": "DATE_OF_BIRTH",
    "DATE_OF_BIRTH": "DATE_OF_BIRTH",
}


def family(entity_type: str) -> str:
    return TYPE_FAMILY.get(entity_type, entity_type)


def _overlap(a: dict, b: dict) -> int:
    return max(0, min(a["end"], b["end"]) - max(a["start"], b["start"]))


def match_spans(gold: list[dict], pred: list[dict], mode: str = "strict") -> dict:
    """
    Greedy 1:1 span matching. Each gold span can be consumed once and each
    prediction can be consumed once. For every gold span the best overlapping
    unused prediction of a compatible type is chosen.

    mode: "strict" (exact boundaries) or "relaxed" (>=50% gold coverage)
    """
    used_pred: set[int] = set()
    tp = 0
    matched_gold = [False] * len(gold)
    pairs: list[tuple[int, int]] = []

    # Evaluate gold spans in order of descending span length so long
    # entities (full address) win over incidental short overlaps.
    order = sorted(range(len(gold)), key=lambda i: gold[i]["end"] - gold[i]["start"], reverse=True)

    for gi in order:
        g = gold[gi]
        best_pi = -1
        best_overlap = 0
        for pi, p in enumerate(pred):
            if pi in used_pred:
                continue
            if family(p["entity_type"]) != family(g["entity_type"]):
                continue
            ov = _overlap(g, p)
            if ov <= 0:
                continue
            if mode == "strict":
                if p["start"] != g["start"] or p["end"] != g["end"]:
                    continue
            else:
                gold_len = max(1, g["end"] - g["start"])
                if ov / gold_len < 0.5:
                    continue
            if ov > best_overlap:
                best_overlap = ov
                best_pi = pi
        if best_pi >= 0:
            used_pred.add(best_pi)
            matched_gold[gi] = True
            tp += 1
            pairs.append((gi, best_pi))

    fp_items = [p for i, p in enumerate(pred) if i not in used_pred]
    fn_items = [g for i, g in enumerate(gold) if not matched_gold[i]]

    precision = tp / (tp + len(fp_items)) if (tp + len(fp_items)) else 0.0
    recall = tp / (tp + len(fn_items)) if (tp + len(fn_items)) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "mode": mode,
        "tp": tp,
        "fp": len(fp_items),
        "fn": len(fn_items),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positives": fp_items,
        "false_negatives": fn_items,
        "pairs": pairs,
    }


def per_type_breakdown(gold: list[dict], pred: list[dict], mode: str = "strict") -> dict:
    """TP / FP / FN counts grouped by gold type family."""
    result = match_spans(gold, pred, mode)
    stats: dict[str, dict] = {}

    def bucket(t: str) -> dict:
        f = family(t)
        return stats.setdefault(f, {"tp": 0, "fp": 0, "fn": 0})

    for gi, _ in result["pairs"]:
        bucket(gold[gi]["entity_type"])["tp"] += 1
    for fp in result["false_positives"]:
        bucket(fp["entity_type"])["fp"] += 1
    for fn in result["false_negatives"]:
        bucket(fn["entity_type"])["fn"] += 1

    for f, s in stats.items():
        p = s["tp"] / (s["tp"] + s["fp"]) if (s["tp"] + s["fp"]) else 0.0
        r = s["tp"] / (s["tp"] + s["fn"]) if (s["tp"] + s["fn"]) else 0.0
        s["precision"] = round(p, 4)
        s["recall"] = round(r, 4)
        s["f1"] = round((2 * p * r / (p + r)) if (p + r) else 0.0, 4)
    return stats


def evaluate(docs: list[dict], engine_detect, limit: int = 40) -> dict:
    """
    Run `engine_detect(text)` over every labelled document and aggregate
    strict + relaxed metrics. Returns a JSON-serialisable report.
    """
    all_gold: list[dict] = []
    all_pred: list[dict] = []
    per_doc: list[dict] = []

    for doc in docs:
        preds = engine_detect(doc["text"])
        pred_dicts = [
            {
                "entity_type": p.entity_type,
                "matched_value": p.matched_value,
                "start": p.start,
                "end": p.end,
                "detection_method": p.detection_method,
                "confidence": p.confidence,
            }
            for p in preds
        ]
        strict = match_spans(doc["gold"], pred_dicts, "strict")
        relaxed = match_spans(doc["gold"], pred_dicts, "relaxed")
        per_doc.append({
            "id": doc["id"],
            "gold": len(doc["gold"]),
            "predicted": len(pred_dicts),
            "strict": {k: strict[k] for k in ("tp", "fp", "fn", "precision", "recall", "f1")},
            "relaxed": {k: relaxed[k] for k in ("tp", "fp", "fn", "precision", "recall", "f1")},
            "false_positives": pred_dicts if not doc["gold"] else strict["false_positives"],
            "false_negatives": strict["false_negatives"],
        })
        all_gold.extend(doc["gold"])
        all_pred.extend(pred_dicts)

    strict = match_spans(all_gold, all_pred, "strict")
    relaxed = match_spans(all_gold, all_pred, "relaxed")

    return {
        "documents": len(docs),
        "gold_spans": len(all_gold),
        "predicted_spans": len(all_pred),
        "strict": {
            "tp": strict["tp"], "fp": strict["fp"], "fn": strict["fn"],
            "precision": strict["precision"], "recall": strict["recall"], "f1": strict["f1"],
            "per_type": per_type_breakdown(all_gold, all_pred, "strict"),
            "false_positives": strict["false_positives"][:limit],
            "false_negatives": strict["false_negatives"][:limit],
        },
        "relaxed": {
            "tp": relaxed["tp"], "fp": relaxed["fp"], "fn": relaxed["fn"],
            "precision": relaxed["precision"], "recall": relaxed["recall"], "f1": relaxed["f1"],
            "per_type": per_type_breakdown(all_gold, all_pred, "relaxed"),
        },
        "per_document": per_doc,
    }
