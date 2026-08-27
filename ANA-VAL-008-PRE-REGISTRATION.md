# ANA-VAL-008 — Real Kubernetes ConfigMap Serialization Falsification

Date: 2026-08-27
Status: PREREGISTERED / FROZEN BEFORE RUNNER EXECUTION
Programme: Authority Non-Amplification (ANA)

## 1. Scientific purpose

ANA-VAL-008 is a new experiment. It is not a rerun, repair, remediation, relabeling, or continuation of ANA-VAL-007 Run #1.

ANA-VAL-007 Run #1 remains immutable. Its exact preregistered oracle failed because live Deployment-controller `/status` reconciliation advanced Deployment `resourceVersion` values and introduced controller-driven serialization interference. No ANA safety violation was observed, but strong real-Kubernetes validation of the same-object design was not established.

The smallest justified question for ANA-VAL-008 is:

> Can authority identity and exact consequence semantics be serialized in a real Kubernetes object whose `resourceVersion` is not ordinarily advanced by an unrelated controller, such that stale or amplified authority cannot produce the tested consequence while legitimate current authority remains live?

## 2. Frozen invariants and non-changes

ANA-VAL-008 does not modify:
- H3;
- the ANA invariant;
- published ContinuityOS Integrated RC-1;
- ANA-VAL-007 Run #1;
- the ANA-VAL-007 runner;
- the ANA-VAL-007 oracle;
- the interpretation of K1/K2/K3.

No new general ANA layer is introduced.

## 3. Experimental object

The tested serialization object is one Kubernetes ConfigMap.

The ConfigMap contains the decision-relevant state needed by Arm B:
- authorityState;
- authorityVersion;
- parentAuthorityVersion where applicable;
- bound ActionDigest;
- consequenceState;
- consequenceCommitId / receipt identity.

A consequence transition is attempted with a conditional full-object update using the exact `metadata.resourceVersion` read during preparation.

No automatic retry after HTTP 409 is permitted.

## 4. Arms

### Arm A — external-authority precheck + consequence ConfigMap CAS

Authority is held outside the consequence ConfigMap.

Sequence:
1. read/check external authority;
2. read consequence ConfigMap and its `resourceVersion`;
3. bind the exact H3 ActionDigest;
4. optionally introduce the preregistered race;
5. update the consequence ConfigMap using the previously read `resourceVersion`.

Purpose:
- negative control;
- demonstrate that object-local CAS cannot atomically serialize authority held outside that object.

### Arm B — same-ConfigMap authority + consequence CAS

Authority state/version, exact H3 ActionDigest, and consequence state exist in the same ConfigMap.

Sequence:
1. read the ConfigMap;
2. validate current authority and exact ActionDigest;
3. retain the observed `resourceVersion`;
4. optionally introduce the preregistered race;
5. attempt the consequence update using the retained `resourceVersion`.

Purpose:
- test whether one controller-independent Kubernetes serialization object can bind authority and consequence without the Deployment `/status` churn seen in ANA-VAL-007.

## 5. Frozen six-case oracle

| Case | Arm | Condition | Frozen expected result |
|---|---|---|---|
| V08-01 | A | Valid external authority; no race; current consequence ConfigMap RV | Consequence update succeeds |
| V08-02 | A | External authority valid at precheck, then revoked before consequence update; consequence ConfigMap RV unchanged | **Expected vulnerability:** consequence update succeeds |
| V08-03 | B | Valid current same-ConfigMap authority + exact ActionDigest; no race | Consequence update succeeds |
| V08-04 | B | Same ConfigMap authority/revocation update serializes first | Prepared consequence uses stale RV and is rejected with HTTP 409; no consequence |
| V08-05 | B | Consequence update serializes first while same-ConfigMap authority is current | Consequence succeeds; later revocation may succeed |
| V08-06 | B | Two competing different consequences prepared from the same RV | At most one consequence succeeds; the other is rejected; never two consequences |

## 6. Primary pass rule

ANA-VAL-008 passes its frozen oracle only if **all 6/6 expected outcomes are observed**.

Additional mandatory safety/liveness conditions:
1. Arm B records **zero** cases in which a stale or revoked same-ConfigMap authority state produces the tested consequence.
2. V08-03 must succeed. A fail-closed system that rejects all legitimate actions does not pass.
3. V08-04 must reject the stale consequence after revocation/version change serializes first.
4. V08-06 must produce no more than one consequence.
5. No post-hoc retry may turn a preregistered 409 into a pass.

Any mismatch freezes the run as a discrepancy before design, runner, retry, resource type, or oracle changes.

## 7. Kill conditions

Arm B is falsified for the tested mechanism if any of the following occurs:
- a consequence succeeds using a stale same-ConfigMap `resourceVersion`;
- a same-ConfigMap authority revocation/version change serializes first and the stale consequence still succeeds;
- a material action differing from the bound H3 ActionDigest is accepted;
- two competing consequences prepared from the same RV both become committed consequences;
- the legitimate V08-03 control cannot succeed under the preregistered no-race condition.

## 8. Evidence required per case

Preserve:
- case ID and arm;
- UTC timestamp;
- client identity/process;
- request method/path;
- exact request body or patch;
- old/read `resourceVersion`;
- presented `resourceVersion`;
- HTTP status;
- response body;
- resulting `resourceVersion`;
- authority state/version;
- parent authority version if used;
- ActionDigest;
- final ConfigMap JSON;
- any external-authority object/record used by Arm A;
- Kubernetes audit event(s);
- observable consequence count;
- pass/fail against this frozen oracle.

## 9. Run-level evidence

Preserve:
- workflow/run identity;
- source commit SHA;
- Kubernetes/kind versions;
- kube-apiserver audit log;
- cluster/control-plane description;
- final namespace and ConfigMaps;
- raw HTTP evidence;
- exact runner/workflow/preregistration SHA-256;
- evidence SHA-256 manifest.

## 10. Interpretation boundary

A 6/6 pass would support only the bounded claim that, in this tested real Kubernetes ConfigMap domain, co-locating authority state/version and exact consequence identity in one CAS-protected object can preserve the tested ANA serialization property without the unrelated Deployment-controller `resourceVersion` churn observed in ANA-VAL-007.

It would not establish:
- universal Authority Non-Amplification;
- cross-object atomicity;
- correctness across all Kubernetes resources/controllers;
- correctness across distributed IAM systems;
- independent replication;
- a new general ANA layer.

A failure must be preserved and may narrow or falsify the tested mechanism.

## 11. Programme stop rule

After ANA-VAL-008, founder-authored ANA engineering stops.

The only remaining scientific gate is at least one independent replication/falsification attempt of the frozen ANA result. After those two gates, the programme must explicitly choose: publish, commercialize a narrowly defined component, or shelve.
