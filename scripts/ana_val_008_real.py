#!/usr/bin/env python3
"""
ANA-VAL-008 runner skeleton.
This file is deliberately limited to the preregistered six-case ConfigMap experiment.
It must not modify H3, the ANA invariant, ANA-VAL-007, or published RC-1.
"""

import argparse, copy, hashlib, json, threading, time, urllib.request, urllib.error
from pathlib import Path
from datetime import datetime, timezone

NAMESPACE = "ana-val-008"
PREFIX = "ana.continuityos/"

def utcnow():
    return datetime.now(timezone.utc).isoformat()

def canonical_digest(action):
    raw = json.dumps(action, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()

class Kube:
    def __init__(self, api, evidence):
        self.api = api.rstrip("/")
        self.evidence = Path(evidence)
        self.evidence.mkdir(parents=True, exist_ok=True)
        self.seq = 0
        self.lock = threading.Lock()

    def request(self, method, path, body=None, client="main"):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(
            self.api + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json",
                     "X-ANA-Client": client}
        )
        status, response = None, ""
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                status = r.status
                response = r.read().decode()
        except urllib.error.HTTPError as e:
            status = e.code
            response = e.read().decode()
        record = {
            "ts": utcnow(), "client": client, "method": method, "path": path,
            "request": body, "status": status, "response": response
        }
        with self.lock:
            self.seq += 1
            (self.evidence / f"http-{self.seq:04d}.json").write_text(
                json.dumps(record, indent=2, sort_keys=True)
            )
        parsed = json.loads(response) if response else None
        return status, parsed

    def cm_path(self, name):
        return f"/api/v1/namespaces/{NAMESPACE}/configmaps/{name}"

    def create_cm(self, name, data):
        body = {"apiVersion":"v1","kind":"ConfigMap",
                "metadata":{"name":name,"namespace":NAMESPACE},
                "data":{k:str(v) for k,v in data.items()}}
        return self.request("POST", f"/api/v1/namespaces/{NAMESPACE}/configmaps", body)

    def get_cm(self, name, client="main"):
        return self.request("GET", self.cm_path(name), client=client)

    def put_cm(self, obj, client="main"):
        return self.request("PUT", self.cm_path(obj["metadata"]["name"]), obj, client=client)

def prepared_consequence(obj, commit_id):
    nxt = copy.deepcopy(obj)
    nxt["data"]["consequenceState"] = "COMMITTED"
    nxt["data"]["consequenceCommitId"] = commit_id
    return nxt

def revoke_same_object(k, name, client="revoker"):
    _, obj = k.get_cm(name, client)
    nxt = copy.deepcopy(obj)
    nxt["data"]["authorityState"] = "REVOKED"
    nxt["data"]["authorityVersion"] = str(int(nxt["data"]["authorityVersion"]) + 1)
    return k.put_cm(nxt, client)

def case_result(case_id, expected, observed, passed, extra=None):
    out = {"case":case_id, "expected":expected, "observed":observed, "pass":bool(passed)}
    if extra: out.update(extra)
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", required=True)
    ap.add_argument("--evidence", required=True)
    args = ap.parse_args()
    k = Kube(args.api, args.evidence)

    # Namespace.
    ns = {"apiVersion":"v1","kind":"Namespace","metadata":{"name":NAMESPACE}}
    k.request("POST", "/api/v1/namespaces", ns)

    action = {"tool":"kubernetes","target":"configmap/consequence",
              "operation":"commit","scope":"ana-val-008"}
    digest = canonical_digest(action)
    results = []

    # V08-01 Arm A valid/no race.
    k.create_cm("v08-01", {"consequenceState":"PENDING","consequenceCommitId":"",
                           "ActionDigest":digest})
    _, obj = k.get_cm("v08-01")
    st, _ = k.put_cm(prepared_consequence(obj, "v08-01-c1"))
    results.append(case_result("V08-01","UPDATE","UPDATE" if 200 <= st < 300 else f"HTTP {st}",
                               200 <= st < 300))

    # V08-02 Arm A external authority race.
    # External authority is intentionally outside the consequence ConfigMap.
    external_authority = {"state":"ACTIVE","version":1}
    k.create_cm("v08-02", {"consequenceState":"PENDING","consequenceCommitId":"",
                           "ActionDigest":digest})
    _, obj = k.get_cm("v08-02")
    assert external_authority["state"] == "ACTIVE"
    external_authority["state"] = "REVOKED"
    external_authority["version"] += 1
    st, _ = k.put_cm(prepared_consequence(obj, "v08-02-c1"))
    results.append(case_result("V08-02","EXPECTED_VULNERABILITY_UPDATE",
                               "UPDATE" if 200 <= st < 300 else f"HTTP {st}",
                               200 <= st < 300,
                               {"externalAuthority":external_authority}))

    # V08-03 Arm B valid/no race.
    k.create_cm("v08-03", {"authorityState":"ACTIVE","authorityVersion":"1",
                           "parentAuthorityVersion":"1","ActionDigest":digest,
                           "consequenceState":"PENDING","consequenceCommitId":""})
    _, obj = k.get_cm("v08-03")
    valid = obj["data"]["authorityState"] == "ACTIVE" and obj["data"]["ActionDigest"] == digest
    st, _ = k.put_cm(prepared_consequence(obj, "v08-03-c1")) if valid else (0, None)
    results.append(case_result("V08-03","UPDATE","UPDATE" if 200 <= st < 300 else f"HTTP {st}",
                               200 <= st < 300))

    # V08-04 Arm B revocation serializes first.
    k.create_cm("v08-04", {"authorityState":"ACTIVE","authorityVersion":"1",
                           "parentAuthorityVersion":"1","ActionDigest":digest,
                           "consequenceState":"PENDING","consequenceCommitId":""})
    _, prepared = k.get_cm("v08-04","consequence")
    revoke_same_object(k, "v08-04","revoker")
    st, _ = k.put_cm(prepared_consequence(prepared, "v08-04-c1"), "consequence")
    _, final = k.get_cm("v08-04")
    no_consequence = final["data"]["consequenceState"] == "PENDING"
    results.append(case_result("V08-04","HTTP 409 / NO CONSEQUENCE",f"HTTP {st}",
                               st == 409 and no_consequence))

    # V08-05 Arm B consequence serializes first.
    k.create_cm("v08-05", {"authorityState":"ACTIVE","authorityVersion":"1",
                           "parentAuthorityVersion":"1","ActionDigest":digest,
                           "consequenceState":"PENDING","consequenceCommitId":""})
    _, prepared = k.get_cm("v08-05","consequence")
    st1, _ = k.put_cm(prepared_consequence(prepared, "v08-05-c1"), "consequence")
    st2, _ = revoke_same_object(k, "v08-05","revoker")
    results.append(case_result("V08-05","CONSEQUENCE UPDATE THEN REVOCATION MAY UPDATE",
                               f"consequence={st1}, revocation={st2}",
                               200 <= st1 < 300 and 200 <= st2 < 300))

    # V08-06 Arm B competing consequences from same RV.
    k.create_cm("v08-06", {"authorityState":"ACTIVE","authorityVersion":"1",
                           "parentAuthorityVersion":"1","ActionDigest":digest,
                           "consequenceState":"PENDING","consequenceCommitId":""})
    _, base = k.get_cm("v08-06")
    barrier = threading.Barrier(3)
    statuses = []
    lock = threading.Lock()
    def competitor(cid):
        candidate = prepared_consequence(base, cid)
        barrier.wait()
        st, _ = k.put_cm(candidate, cid)
        with lock: statuses.append(st)
    t1 = threading.Thread(target=competitor,args=("v08-06-a",))
    t2 = threading.Thread(target=competitor,args=("v08-06-b",))
    t1.start(); t2.start(); barrier.wait(); t1.join(); t2.join()
    successes = sum(1 for s in statuses if 200 <= s < 300)
    results.append(case_result("V08-06","AT MOST ONE CONSEQUENCE",
                               statuses, successes <= 1 and successes == 1))

    summary = {
        "experiment":"ANA-VAL-008",
        "timestamp":utcnow(),
        "results":results,
        "passed":all(r["pass"] for r in results),
        "count_pass":sum(r["pass"] for r in results),
        "count_total":len(results),
        "claim_boundary":"Real Kubernetes evidence only if executed against a genuine kube-apiserver/storage path."
    }
    Path(args.evidence, "ANA-VAL-008-RESULTS.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    raise SystemExit(0 if summary["passed"] else 1)

if __name__ == "__main__":
    main()
