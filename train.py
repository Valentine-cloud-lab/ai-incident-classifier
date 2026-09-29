"""
train.py
Trains the TF-IDF + multinomial logistic regression classifier with
scikit-learn, selects the regularization strength C by 5-fold stratified
cross-validation (lowest log loss) on the training set only, and exports model/model.json for
the dependency-free Lambda runtime.

After export, the script reloads model.json through src/classifier.py and
confirms the pure-Python probabilities match scikit-learn to within 1e-6 on
every training record. A mismatch stops the build.

Run:  python training/train.py
"""
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.pipeline import make_pipeline

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from classifier import IncidentClassifier, analyze  # noqa: E402

CLASSES = ["IDENTITY_ACCESS", "NETWORK_EXPOSURE", "DATA_PROTECTION",
           "COMPUTE_AVAILABILITY", "THREAT_DETECTION"]


def load(name):
    with open(ROOT / "data" / name, encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh]
    return [r["text"] for r in rows], [r["label"] for r in rows]


def build(c_value):
    vec = TfidfVectorizer(analyzer=analyze, sublinear_tf=True, min_df=2, norm="l2")
    clf = LogisticRegression(C=c_value, max_iter=5000, class_weight="balanced")
    return make_pipeline(vec, clf)


def main():
    texts, labels = load("alerts_train.jsonl")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=605)

    # Model selection on training data only. The test and hard sets stay unseen.
    # Selection metric is log loss, not F1. Template-built training data are
    # close to linearly separable, so F1 saturates at 1.0 for every C and
    # cannot separate candidates. Log loss rewards calibrated probabilities,
    # which matter here because a probability threshold gates auto-routing.
    # The grid stops at C=16 to limit overfitting on near-separable data.
    results = {}
    for c_value in [0.5, 1.0, 2.0, 4.0, 8.0, 16.0]:
        f1 = cross_val_score(build(c_value), texts, labels, cv=cv, scoring="f1_macro").mean()
        ll = -cross_val_score(build(c_value), texts, labels, cv=cv, scoring="neg_log_loss").mean()
        results[c_value] = {"macro_f1": round(float(f1), 4), "log_loss": round(float(ll), 4)}
        print(f"C={c_value:<5} 5-fold macro-F1={f1:.4f}  log-loss={ll:.4f}")
    chosen = min(results, key=lambda c: results[c]["log_loss"])
    print(f"chosen C = {chosen}")

    pipe = build(chosen).fit(texts, labels)
    vec, clf = pipe.named_steps["tfidfvectorizer"], pipe.named_steps["logisticregression"]
    order = [list(clf.classes_).index(c) for c in CLASSES]  # fixed class order

    features = {}
    for token, idx in vec.vocabulary_.items():
        features[token] = [round(float(vec.idf_[idx]), 8)] + \
                          [round(float(clf.coef_[k][idx]), 8) for k in order]

    model = {
        "version": datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
        "algorithm": "tfidf(1-2gram, sublinear, l2) + multinomial logistic regression",
        "C": chosen,
        "cv_results": results,
        "classes": CLASSES,
        "intercept": [round(float(clf.intercept_[k]), 8) for k in order],
        "features": features,
    }
    raw = json.dumps(model, separators=(",", ":"), sort_keys=True)
    (ROOT / "model").mkdir(exist_ok=True)
    (ROOT / "model" / "model.json").write_text(raw, encoding="utf-8")
    sha = hashlib.sha256(raw.encode()).hexdigest()
    (ROOT / "model" / "model.sha256").write_text(sha + "\n")
    print(f"exported {len(features)} features, sha256={sha}")

    # Parity check: pure-Python inference must match scikit-learn.
    runtime = IncidentClassifier.from_json(raw)
    sk = pipe.predict_proba(texts)
    worst = 0.0
    for i, text in enumerate(texts):
        mine = runtime.predict_proba(text)
        for k, cls in enumerate(CLASSES):
            worst = max(worst, abs(mine[cls] - sk[i][list(clf.classes_).index(cls)]))
    print(f"parity check: max |p_python - p_sklearn| = {worst:.2e}")
    if worst > 1e-6:
        raise SystemExit("parity check failed")


if __name__ == "__main__":
    np.random.seed(605)
    main()
