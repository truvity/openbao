# Platform prerequisites per capability level

What the platform must already provide before each capability level of
[the decision guide](decision-guide.md) works, and **how to check each item**.
The charts and the Go module assume these and never create them
([doctrine.md](doctrine.md#ownership-contract)); every check below is
read-only.

The workload side (what an application does with the identity it is given)
is a different page: see truvity/policy mTLS guide. This page is only what
the platform owes the workload.

**Conventions.** Examples use `example.org`, an environment `dev`, a project
`shop` and a cluster `east`; names such as `jwt-east`, `identity-dev` and
`issuer-identity` are inputs in a real install. Commands assume `BAO_ADDR`
and a token that can read the namespace in question, and `kubectl` pointed at
the cluster you mean (check `kubectl config current-context` first: a green
check against the wrong cluster proves nothing). A level includes every item
of the levels below it; each section lists only what is new.

| Level | Section |
|---|---|
| 0 | [a server](#level-0-a-server) |
| 1 | [secrets](#level-1-secrets) |
| 2 | [SSH](#level-2-ssh) |
| 3 | [an internal PKI](#level-3-an-internal-pki) |
| 4 | [workload identity](#level-4-workload-identity) |
| 5 | [enforcement](#level-5-enforcement) |

## Level 0: a server

**0.1 The server is up, unsealed, and has every Raft voter.**

```sh
kubectl -n openbao get pods -l app.kubernetes.io/name=openbao
bao status                       # Sealed false; Initialized true
bao operator raft list-peers     # every pod listed as a voter
```

**0.2 The seal is the one you chose.** With auto-unseal the seal type is the
KMS one; without it you unseal by hand after every restart.

```sh
bao status -format=json | jq -r .type        # e.g. awskms, not shamir
kubectl -n openbao exec openbao-0 -- sh -c 'env | grep -i -E "AWS_(ROLE|WEB)"'   # pod identity injected
```

**0.3 A serving certificate exists and is renewed.**

```sh
kubectl -n openbao get certificate            # READY True
openssl s_client -connect "$(echo "$BAO_ADDR" | sed 's|https://||')" </dev/null 2>/dev/null \
  | openssl x509 -noout -enddate -issuer
```

**0.4 The server reloads a renewed certificate** (`tlsReload` sidecar with
`shareProcessNamespace: true`).

```sh
kubectl -n openbao get pod openbao-0 -o jsonpath='{.spec.shareProcessNamespace}{"\n"}'   # true
kubectl -n openbao get pod openbao-0 -o jsonpath='{.spec.containers[*].name}{"\n"}'      # includes the reload sidecar
```

**0.5 Backups are real: a snapshot ran and a restore check opened it.**

```sh
kubectl -n openbao create job --from=cronjob/<snapshot-cronjob> first-snapshot
kubectl -n openbao logs job/first-snapshot --tail=5
kubectl -n openbao create job --from=cronjob/<restore-check-cronjob> first-restore-check
kubectl -n openbao logs job/first-restore-check --tail=5     # the pass line names the snapshot it opened
```

**0.6 The server's `disable_standby_reads` is `true`** (the apply must write to
the active node).

```sh
kubectl -n openbao get configmap -o yaml | grep -n disable_standby_reads
```

**0.7 NetworkPolicy for the server** (the server reachable from clients and
peers, the jobs from nothing).

```sh
kubectl -n openbao get networkpolicy
kubectl -n openbao describe networkpolicy openbao-ingress | sed -n '/Allowing ingress/,$p'
```

## Level 1: secrets

**1.1 A per-environment namespace exists, with its KV mount.**

```sh
bao namespace list                                  # dev/
bao secrets list -namespace=dev                     # kv/ (type kv, version 2)
bao read -namespace=dev kv/config                   # the mount answers
```

**1.2 The operator door exists in root** (bootstrap), and root-token use is
retired ([bootstrap.md](bootstrap.md)).

```sh
bao auth list                                       # a jwt mount for the operators' issuer
bao read sys/policies/acl/operator                  # the operator policy
bao list identity/group/name                        # the operators' external group
```

**1.3 The cluster's ServiceAccount issuer is reachable from OpenBAO, through
the per-cluster JWT mount.** One cluster is one issuer is one mount; a second
cluster is a second mount.

```sh
# the issuer the cluster signs tokens with
kubectl get --raw /.well-known/openid-configuration | jq -r .issuer
# the mount trusts that issuer, at a URL OpenBAO itself can reach
bao read -namespace=dev auth/jwt-east/config        # oidc_discovery_url, bound_issuer
kubectl -n openbao exec openbao-0 -- \
  wget -qO- "$(bao read -namespace=dev -field=oidc_discovery_url auth/jwt-east/config)/.well-known/openid-configuration" | jq -r .jwks_uri
```

**1.4 A login works end to end** (a workload role bound to an audience and a
subject).

```sh
TOKEN=$(kubectl -n shop create token shop-api --audience=openbao)
bao write -namespace=dev auth/jwt-east/login role=shop-api jwt="$TOKEN"   # a token with the role's policies
bao read -namespace=dev auth/jwt-east/role/shop-api                      # bound_audiences, bound_subject
```

**1.5 External Secrets Operator is present and each store is valid.**

```sh
kubectl get crd clustersecretstores.external-secrets.io
kubectl get clustersecretstore                      # READY True, STATUS Valid
```

**1.6 The restore check's canary is in every namespace it reads.**

```sh
bao kv get -namespace=dev kv/restore-canary         # {namespace: dev}
```

**1.7 The roles and policies the charts name exist** (`snapshot.baoRole`,
`restoreCheck.baoRole`, `stores[].role`, `writers[].name`).

```sh
bao list auth/jwt/role                              # root: the snapshot and restore-check roles
bao list -namespace=dev auth/jwt-east/role          # the stores' roles
```

## Level 2: SSH

**2.1 The aws auth plugin is registered**, by exactly one of the two paths
(declaratively in the server preset, or a command on disk).

```sh
bao plugin list auth | grep aws
bao read sys/plugins/catalog/auth/aws               # version equals the mount's pluginVersion
```

**2.2 The server can download the plugin, or has it** (egress to the registry).

```sh
kubectl -n openbao logs openbao-0 | grep -E "downloaded and validated plugin|failed to download plugin"
```

**2.3 The SSH user and host CAs exist, as separate keys.**

```sh
bao read -namespace=dev -field=public_key ssh/config/ca
bao read -namespace=dev -field=public_key ssh-host/config/ca      # not equal to the line above
```

**2.4 Roles refuse a root principal and wildcards.**

```sh
bao read -namespace=dev ssh/roles/operators         # allowed_users, no root, no *
```

**2.5 STS is reachable** (egress to the AWS STS endpoint) and a host can
renew.

```sh
kubectl -n openbao exec openbao-0 -- wget -qO- --spider https://sts.amazonaws.com
openbao-hostcert --help                              # on a host: the renewer is installed
systemctl status openbao-hostcert.timer              # on a host
```

**2.6 Clients trust the host CA with one line.**

```sh
grep '@cert-authority' ~/.ssh/known_hosts /etc/ssh/ssh_known_hosts
```

## Level 3: an internal PKI

**3.1 The root key exists, multi-region, and every Sign is announced.**

```sh
aws kms describe-key --key-id alias/private-pki/root/2026 --query 'KeyMetadata.[MultiRegion,KeySpec,KeyUsage]'
aws kms get-key-policy --key-id alias/private-pki/root/2026 --policy-name default | jq .   # admin cannot sign; ceremony role can
aws cloudtrail get-trail-status --name <trail>       # IsLogging true, multi-region
```

**3.2 The contract validates, and every trusted generation resolves to its
committed artifact.**

```sh
openbaoctl pki verify-intermediate --contract pki.yaml --generation 2026 --trust-domain private
```

**3.3 The environment's PKI mount and issuing CA exist**, signed by the
domain intermediate, plus the leaf roles.

```sh
bao secrets list -namespace=dev | grep pki
bao read -namespace=dev pki/issuers                  # the environment's issuing CA
bao list -namespace=dev pki/roles                    # private, service, client, ...
bao read -namespace=dev pki/role/private             # allowed_domains inside the private zone
```

**3.4 cert-manager is installed with a Vault-type issuer that can log in**, per
issuer, with the audience `vault://<issuer-name>`.

```sh
kubectl -n cert-manager get deploy
kubectl get clusterissuer                            # READY True for each OpenBAO-backed issuer
bao read -namespace=dev auth/jwt-east/role/issuer-private      # bound_audiences: vault://example-private
```

**3.5 The blanket approver is still ON** until level 4 (or you have approver
policies for everything). Know which state you are in.

```sh
kubectl -n cert-manager get deploy cert-manager -o jsonpath='{.spec.template.spec.containers[0].args}{"\n"}'
```

**3.6 trust-manager is installed and its private bundle is delivered.**

```sh
kubectl get crd bundles.trust.cert-manager.io
kubectl get bundle                                   # SYNCED True
kubectl -n shop get configmap -o name | grep ca-certificates   # delivered in every namespace
```

**3.7 One disposable certificate per issuer proves login, chain and renewal**
(`certificates:` in the chart) before any workload changes its `issuerRef`.

```sh
kubectl get certificate -A | grep -v True            # nothing listed
```

**3.8 Break-glass is rehearsed** (yearly): a leaf can be signed offline.

```sh
openbaoctl pki sign-emergency-server --contract pki.yaml --generation 2026 --dns-name bao.example.internal --csr emergency.csr --print-template
```

## Level 4: workload identity

Everything here is per environment. The order is the order of the checks:
CA, then trust, then approval, then the namespace.

**4.1 The environment's identity CA exists, root-signed, with an exact URI
constraint, and an `identity` role bounded to the trust domain.**

```sh
bao read -namespace=dev pki/issuer/identity-dev      # signed by the root, not an intermediate
bao read -namespace=dev -field=certificate pki/issuer/identity-dev \
  | openssl x509 -noout -text | grep -A2 "Name Constraints"   # URI:dev.example.internal (exact), critical
bao read -namespace=dev pki/roles/identity           # allowed_uri_sans spiffe://dev.example.internal/*, use_csr_sans false, no DNS names
```

**4.2 The login role the identity issuer uses accepts only that issuer's
audience.**

```sh
bao read -namespace=dev auth/jwt-east/role/issuer-identity    # bound_audiences: vault://example-identity
```

**4.3 The identity role accepts the driver's P-256 key.** The driver cannot
generate another; a role requiring 384 refuses after the approver approved.

```sh
bao read -namespace=dev -field=key_type pki/roles/identity    # ec
bao read -namespace=dev -field=key_bits pki/roles/identity    # 256 or lower, not 384
```

**4.4 cert-manager runs with the blanket approver OFF.**

```sh
kubectl -n cert-manager get deploy cert-manager -o jsonpath='{.spec.template.spec.containers[0].args}{"\n"}' \
  | grep -- '--controllers=\*,-certificaterequests-approver'
# or, as the CI assertion:
approvercheck --live --context east --policies policies.yaml --require-blanket-approver-off \
  --identity-signer clusterissuers.cert-manager.io/example-identity
```

**4.5 approver-policy is installed, its signer list excludes the identity
issuer, and one policy exists per non-identity issuer.**

```sh
kubectl -n cert-manager get deploy cert-manager-approver-policy
kubectl -n cert-manager get deploy cert-manager-approver-policy -o yaml | grep -A6 approve-signer-names
kubectl get certificaterequestpolicy                 # READY True, one per issuer, none for example-identity
kubectl get certificaterequestpolicy -o yaml | grep -c 'spiffe:'   # 0
```

**4.6 RBAC: cert-manager may `use` exactly those policies, and nothing else may
approve the identity issuer.**

```sh
SA=system:serviceaccount:cert-manager:cert-manager
for p in $(kubectl get certificaterequestpolicy -o name | cut -d/ -f2); do
  echo -n "$p: "; kubectl auth can-i use certificaterequestpolicies/"$p" --as="$SA"
done
kubectl auth can-i approve signers/clusterissuers.cert-manager.io/example-identity --as="$SA"   # no
kubectl get clusterrole -o yaml | grep -B3 'clusterissuers.cert-manager.io/example-identity'    # only the driver's role
```

**4.7 csi-driver-spiffe: trust domain, issuer, and `sourceCABundle`.**

```sh
kubectl -n cert-manager get daemonset cert-manager-csi-driver-spiffe
helm -n cert-manager get values cert-manager-csi-driver-spiffe | grep -E 'trustDomain|issuer|sourceCABundle|signerName|autoApproveNonSPIFFE'
#   trustDomain: dev.example.internal   issuer.name: example-identity
#   sourceCABundle: /etc/csi-spiffe-trust/ca.pem     autoApproveNonSPIFFE: false
kubectl -n cert-manager get configmap example-identity-ca -o jsonpath='{.data}' | head -c 200   # delivered to the driver's namespace
```

**4.8 trust-manager bundles hold only the environment's own CA.**

```sh
kubectl get bundle example-identity-ca -o jsonpath='{.spec.sources}{"\n"}'
kubectl -n shop get configmap example-identity-ca -o jsonpath='{.data.example-identity-ca\.pem}' \
  | openssl x509 -noout -subject -ext nameConstraints    # one CA: this environment's
kubectl -n shop get configmap example-identity-ca -o jsonpath='{.data.example-identity-ca\.pem}' \
  | grep -c 'BEGIN CERTIFICATE'                          # 1
```

**4.9 Each opted-in namespace has the label and the request permission.** The
driver creates its requests **as the pod's own ServiceAccount**.

```sh
kubectl get ns shop --show-labels | grep 'identity.example.org/workload-identity=true'
kubectl -n shop get role,rolebinding spiffe-certificaterequests
kubectl auth can-i create certificaterequests -n shop --as=system:serviceaccount:shop:shop-api   # yes
```

**4.10 NetworkPolicies cover the authenticated ports.** Default-deny is the
baseline; the authenticated port is reachable only from its callers; the probe
port is separate.

```sh
kubectl -n shop get networkpolicy
kubectl -n shop describe networkpolicy | grep -E 'Allowing ingress|Port|From'
kubectl -n shop get svc -o custom-columns=NAME:.metadata.name,PORTS:.spec.ports[*].appProtocol
```

**4.11 Each component runs as its own ServiceAccount.**

```sh
kubectl -n shop get deploy,sts,job,cronjob -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.template.spec.serviceAccountName}{"\n"}{end}' \
  | sort -k2 | uniq -f1 -d      # prints nothing
```

**4.12 Issuance-chain alerts are on and load.** `IssuanceCertificateNotReady`,
`IssuanceCsiDriverSpiffeUnavailable`, `IssuanceApproverPolicyUnavailable`,
renewal and expiry rules, `IssuanceMetricsAbsent`; the opt-in denial and CA
expiry rules need the exports described in
[trust/issuance.md](trust/issuance.md#what-the-metrics-cover-and-the-gaps).

```sh
kubectl get vmrule,prometheusrule -A | grep -i issuance          # the object exists
# on the ruler, every Issuance* rule is loaded and not erroring:
curl -s "$RULER/api/v1/rules" | jq -r '.data.groups[].rules[] | select(.name|startswith("Issuance")) | "\(.name) \(.health)"'
# the metric the rules depend on is scraped:
curl -s "$PROM/api/v1/query" --data-urlencode 'query=certmanager_clock_time_seconds' | jq '.data.result|length'   # >= 1
```

**4.13 The approver proof runs in CI, on every change to the layer.** It must
cover every request shape: render the tenant `Certificate`s and check them.

```sh
helm template shop charts/openbao-consumers -f values.yaml --show-only templates/approver.yaml > policies.yaml
helm template shop charts/openbao-consumers -f values.yaml --show-only templates/certificates.yaml > certs.yaml
approvercheck --policies policies.yaml --certificates certs.yaml            # exit 0
approvercheck --policies policies.yaml --live --context east \
  --identity-signer clusterissuers.cert-manager.io/example-identity \
  --require-blanket-approver-off                                            # exit 0
```

**4.14 The refusal test** passes, and its namespace and ServiceAccount are
kept so it can be re-run ([approver.md](approver.md#cutover-runbook)). A
request for another workload's URI must end `Denied`.

```sh
kubectl -n identity-smoke get certificaterequest -o custom-columns=NAME:.metadata.name,APPROVED:.status.conditions[?(@.type=="Approved")].status,DENIED:.status.conditions[?(@.type=="Denied")].status,MSG:.status.conditions[?(@.type=="Denied")].message
# the forged request: Denied, "unexpected SPIFFE ID requested", no .status.certificate
```

## Level 5: enforcement

**5.1 The cluster supports `ValidatingAdmissionPolicy` (Kubernetes 1.30 or
later).**

```sh
kubectl version -o json | jq -r .serverVersion.gitVersion
kubectl api-resources --api-group=admissionregistration.k8s.io | grep validatingadmissionpolic
```

**5.2 The policy and its binding exist, and start as a dry run.**

```sh
kubectl get validatingadmissionpolicy,validatingadmissionpolicybinding | grep mtls-enforced
kubectl get validatingadmissionpolicybinding -o jsonpath='{.items[*].spec.validationActions}{"\n"}'   # ["Warn","Audit"], then ["Deny"]
```

**5.3 Only labelled namespaces are in scope.**

```sh
kubectl get ns -l mtls-level=enforced
kubectl get validatingadmissionpolicybinding -o jsonpath='{.items[*].spec.matchResources.namespaceSelector}{"\n"}'
```

**5.4 The dry run is quiet before `Deny`.** A full apply of the namespace prints
no `Warning:` for the policy.

```sh
kubectl apply --dry-run=server -n shop -f rendered/ 2>&1 | grep -i warning   # nothing
```

**5.5 Every exemption has a reason.**

```sh
kubectl get pods,svc,deploy -A -o json \
  | jq -r '.items[] | select(.metadata.annotations["mtls-exempt"]!=null or .spec.template.metadata.annotations["mtls-exempt"]!=null) | "\(.kind)/\(.metadata.name): \(.metadata.annotations["mtls-exempt"] // .spec.template.metadata.annotations["mtls-exempt"])"'
# no entry has an empty reason
```

**5.6 The refusal holds** (after `Deny`): a pod on the `default` ServiceAccount,
or without the identity volume, is refused at apply.

```sh
kubectl -n shop run probe --image=registry.example.org/probe:1 --dry-run=server   # Forbidden, names the rule
```

**5.7 The calls catalogue names every caller before a component is `strict`.**
This is a render-time check in the platform that renders the project; see
[trust/workload-identity.md](trust/workload-identity.md#the-calls-catalogue).

**5.8 Level 4's checks still pass.** A level-5 install that no longer passes
4.4, 4.13 and 4.14 has enforcement in front of an approver nobody proved.
