from app import corroborate

BASE_CLAIM = {"subject": "77k9wq.example", "predicate": "resolves_to", "value": "203.0.113.20"}

req_supported_high = {
    "claim": BASE_CLAIM,
    "asOf": "2026-08-01T00:00:00Z",
    "stalenessDays": 120,
    "sources": [
        {"id": "s1", "type": "dns", "origin": "resolver-a",
         "observedAt": "2026-07-30T00:00:00Z", "value": "203.0.113.20", "authoritative": False},
        {"id": "s2", "type": "ct_log", "origin": "ct-b",
         "observedAt": "2026-07-25T00:00:00Z", "value": "203.0.113.20", "authoritative": False},
    ],
}
print("supported/high:", corroborate(req_supported_high))

req_contradicted = {
    "claim": BASE_CLAIM,
    "asOf": "2026-08-01T00:00:00Z",
    "stalenessDays": 120,
    "sources": [
        {"id": "s1", "type": "dns", "origin": "resolver-a",
         "observedAt": "2026-07-30T00:00:00Z", "value": "203.0.113.20", "authoritative": False},
        {"id": "s2", "type": "registry", "origin": "registry-1",
         "observedAt": "2026-07-29T00:00:00Z", "value": "198.51.100.9", "authoritative": True},
    ],
}
print("contradicted:", corroborate(req_contradicted))

req_unverified_single = {
    "claim": BASE_CLAIM,
    "asOf": "2026-08-01T00:00:00Z",
    "stalenessDays": 120,
    "sources": [
        {"id": "s1", "type": "dns", "origin": "resolver-a",
         "observedAt": "2026-07-30T00:00:00Z", "value": "203.0.113.20", "authoritative": False},
    ],
}
print("unverified/single:", corroborate(req_unverified_single))