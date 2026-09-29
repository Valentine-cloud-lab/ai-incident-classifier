"""
classifier.py
Pure-Python inference for the incident classifier.

Why pure Python: the Lambda deployment package stays small with zero
third-party dependencies. Training uses scikit-learn offline (training/train.py),
then exports the TF-IDF vocabulary, IDF weights, and logistic regression
coefficients to model/model.json. This module reproduces sklearn's
TfidfVectorizer(sublinear_tf=True, norm="l2") and multinomial
LogisticRegression.predict_proba (parity checked in training/train.py).
"""
import json
import math
import re
from collections import Counter

# ---------------------------------------------------------------------------
# Text normalization, shared by training and inference so features match.
# Resource IDs, IPs, and account numbers carry no category signal on their own,
# so each one collapses to a placeholder token. Resource-type prefixes (sg-, i-)
# survive because they carry signal (a security group versus an instance).
# ---------------------------------------------------------------------------
_RULES = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), " accesskeyid "),
    (re.compile(r"0\.0\.0\.0/0|::/0"), " anyaddress "),
    (re.compile(r"arn:aws[\w:/\-\.\*]*", re.I), " awsarn "),
    (re.compile(r"\b(i|sg|vpc|subnet|vol|snap|eni|acl|rtb|igw|nat)-[0-9a-f]{6,17}\b", re.I),
     lambda m: " " + m.group(1).lower() + "id "),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b"), " ipaddr "),
    (re.compile(r"\bport\s+(22|23|445|1433|3306|3389|5432)\b", re.I), " port adminport "),
    (re.compile(r"\b\d{12}\b"), " acctid "),
    (re.compile(r"\b\d+(?:\.\d+)?\b"), " num "),
]
_TOKEN = re.compile(r"[a-z][a-z0-9]+")


def normalize(text: str) -> str:
    """Replace volatile identifiers with stable placeholder tokens."""
    out = text or ""
    for pattern, repl in _RULES:
        out = pattern.sub(repl, out)
    return out.lower()


def analyze(text: str) -> list:
    """Return unigram and bigram features for one alert."""
    tokens = _TOKEN.findall(normalize(text))
    bigrams = [f"{a} {b}" for a, b in zip(tokens, tokens[1:])]
    return tokens + bigrams


class IncidentClassifier:
    """Loads model.json and scores alert text against each category."""

    def __init__(self, model: dict):
        self.classes = model["classes"]
        self.intercept = model["intercept"]
        # features maps token -> [idf, coef_class0, coef_class1, ...]
        self.features = model["features"]
        self.version = model.get("version", "unknown")

    @classmethod
    def from_json(cls, raw: str) -> "IncidentClassifier":
        return cls(json.loads(raw))

    def _vectorize(self, text: str) -> dict:
        counts = Counter(t for t in analyze(text) if t in self.features)
        weights = {t: (1.0 + math.log(c)) * self.features[t][0] for t, c in counts.items()}
        norm = math.sqrt(sum(w * w for w in weights.values()))
        return {t: w / norm for t, w in weights.items()} if norm else {}

    def predict_proba(self, text: str) -> dict:
        """Return {category: probability} using a numerically stable softmax."""
        vec = self._vectorize(text)
        scores = list(self.intercept)
        for token, weight in vec.items():
            coefs = self.features[token]
            for k in range(len(scores)):
                scores[k] += weight * coefs[k + 1]
        top = max(scores)
        exps = [math.exp(s - top) for s in scores]
        total = sum(exps)
        return {c: e / total for c, e in zip(self.classes, exps)}

    def predict(self, text: str) -> tuple:
        """Return (category, confidence) for the highest-probability class."""
        probs = self.predict_proba(text)
        label = max(probs, key=probs.get)
        return label, probs[label]
