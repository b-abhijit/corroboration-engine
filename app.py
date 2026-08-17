from datetime import datetime, timezone
from flask import Flask, request, jsonify

app = Flask(__name__)

VALID_TYPES = {"dns", "ct_log", "registry", "archive", "scan"}


def parse_iso8601(value):
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def is_valid_source_shape(src):
    if not isinstance(src, dict):
        return False
    for field in ("id", "origin", "value", "observedAt"):
        if not isinstance(src.get(field), str):
            return False
    if src.get("type") not in VALID_TYPES:
        return False
    return True


def request_is_invalid(body):
    if not isinstance(body, dict):
        return True
    claim = body.get("claim")
    if not isinstance(claim, dict) or not isinstance(claim.get("value"), str):
        return True
    if parse_iso8601(body.get("asOf")) is None:
        return True
    staleness = body.get("stalenessDays")
    if isinstance(staleness, bool) or not isinstance(staleness, (int, float)):
        return True
    if not isinstance(body.get("sources"), list):
        return True
    return False


def result(verdict, confidence, ids):
    return {
        "verdict": verdict,
        "confidence": confidence,
        "corroboratingSources": sorted(ids),
    }


def corroborate(body):
    if request_is_invalid(body):
        return result("invalid", "low", [])

    claim = body["claim"]
    claim_value = claim["value"]
    as_of = parse_iso8601(body["asOf"])
    staleness_days = float(body["stalenessDays"])
    raw_sources = body["sources"]

    valid_sources = [s for s in raw_sources if is_valid_source_shape(s)]

    fresh_sources = []
    for s in valid_sources:
        observed_at = parse_iso8601(s["observedAt"])
        if observed_at is None:
            continue
        age_days = (as_of - observed_at).total_seconds() / 86400.0
        if age_days <= staleness_days:
            fresh_sources.append(s)

    contradicting = [
        s for s in fresh_sources
        if s.get("authoritative") is True and s["value"] != claim_value
    ]
    if contradicting:
        ids = [s["id"] for s in contradicting]
        return result("contradicted", "low", ids)

    agreeing = [s for s in fresh_sources if s["value"] == claim_value]

    best_by_origin = {}
    for s in agreeing:
        origin = s["origin"]
        if origin not in best_by_origin or s["id"] < best_by_origin[origin]["id"]:
            best_by_origin[origin] = s

    representatives = list(best_by_origin.values())

    if len(representatives) >= 2:
        distinct_types = {s["type"] for s in representatives}
        confidence = "high" if len(distinct_types) >= 2 else "medium"
        ids = [s["id"] for s in representatives]
        return result("supported", confidence, ids)

    return result("unverified", "low", [])


@app.route("/corroborate", methods=["POST"])
def corroborate_endpoint():
    body = request.get_json(silent=True)
    return jsonify(corroborate(body))

if __name__ == "__main__":
    app.run(debug=True)