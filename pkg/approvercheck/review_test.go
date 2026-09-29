package approvercheck

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

// chartPolicies is the openbao-consumers chart's own rendered approver
// output (`just golden` regenerates it): one source of truth, so a chart
// change that stops approving what it should fails here, not in a cluster.
// It holds exact policies for example-private (ClusterIssuer, dnsNames
// *.devel.example.internal, one commonName) and example-origin
// (*.example.com, 720h, P-384 only), the allow-all namespaced-issuers
// policy, and NO policy for the example-identity issuer.
const spiffeURI = "spiffe://example.internal/ns/a/sa/b"

const apiHost = "api.devel.example.internal"

const chartPolicies = "../../tests/golden/openbao-consumers/approver-policy.yaml"

type csrSpec struct {
	cn        string
	dns       []string
	uris      []string
	org       []string
	country   []string
	curve     elliptic.Curve // nil: P-384
	rsaBits   int            // >0: an RSA key
	otherName bool
}

func makeCSR(t *testing.T, s csrSpec) []byte {
	t.Helper()

	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: s.cn, Organization: s.org, Country: s.country},
		DNSNames: s.dns,
	}
	for _, raw := range s.uris {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		tmpl.URIs = append(tmpl.URIs, u)
	}
	if s.otherName {
		// SAN with a single otherName [0] entry (id 1.2.3.4, UTF8 "x").
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
			Value: []byte{0x30, 0x0b, 0xa0, 0x09, 0x06, 0x03, 0x2a, 0x03, 0x04, 0xa0, 0x02, 0x0c, 0x00},
		})
	}

	var der []byte
	var err error
	if s.rsaBits > 0 {
		key, kerr := rsa.GenerateKey(rand.Reader, s.rsaBits)
		require.NoError(t, kerr)
		der, err = x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	} else {
		curve := s.curve
		if curve == nil {
			curve = elliptic.P384()
		}
		key, kerr := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, kerr)
		der, err = x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	}
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func makeCR(t *testing.T, issuer, kind string, hours int, s csrSpec) *cmapi.CertificateRequest {
	t.Helper()

	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "leaf-1", Namespace: "app"},
		Spec: cmapi.CertificateRequestSpec{
			Request:   makeCSR(t, s),
			IssuerRef: cmmeta.IssuerReference{Name: issuer, Kind: kind, Group: "cert-manager.io"},
		},
	}
	if hours > 0 {
		cr.Spec.Duration = &metav1.Duration{Duration: time.Duration(hours) * time.Hour}
	}
	return cr
}

func loadChartPolicies(t *testing.T) []policyapi.CertificateRequestPolicy {
	t.Helper()
	policies, err := LoadPolicies(chartPolicies)
	require.NoError(t, err)
	require.Len(t, policies, 3)
	return policies
}

func TestChartPoliciesDecideEveryShape(t *testing.T) {
	policies := loadChartPolicies(t)
	opts := Options{SkipSigners: []string{"clusterissuers.cert-manager.io/example-identity"}}

	p256 := elliptic.P256()
	cases := []struct {
		name    string
		issuer  string
		kind    string
		hours   int
		spec    csrSpec
		want    string
		mention string // a substring the detail must carry
	}{
		{"private leaf, P-384", "example-private", "ClusterIssuer", 720, csrSpec{dns: []string{apiHost}}, OutcomeApproved, "example-private"},
		{"private leaf, P-256 tolerated", "example-private", "ClusterIssuer", 720, csrSpec{dns: []string{apiHost}, curve: p256}, OutcomeApproved, ""},
		{
			name: "private leaf with the allowed commonName", issuer: "example-private", kind: "ClusterIssuer", hours: 720,
			spec: csrSpec{cn: "smoke.devel.example.internal", dns: []string{"smoke.devel.example.internal"}},
			want: OutcomeApproved, mention: "",
		},
		{"no duration set on the request", "example-private", "ClusterIssuer", 0, csrSpec{dns: []string{apiHost}}, OutcomeDenied, "maxDuration"},
		{"foreign host", "example-private", "ClusterIssuer", 720, csrSpec{dns: []string{"api.evil.example.com"}}, OutcomeDenied, "dnsNames"},
		{
			name: "the apex is not the wildcard", issuer: "example-private", kind: "ClusterIssuer", hours: 720,
			spec: csrSpec{dns: []string{"devel.example.internal"}},
			want: OutcomeDenied, mention: "dnsNames",
		},
		{
			name: "a commonName the policy does not allow", issuer: "example-private", kind: "ClusterIssuer", hours: 720,
			spec: csrSpec{cn: "other.example.internal", dns: []string{apiHost}},
			want: OutcomeDenied, mention: "commonName",
		},
		{
			name: "P-521 is above the ceiling", issuer: "example-private", kind: "ClusterIssuer", hours: 720,
			spec: csrSpec{dns: []string{apiHost}, curve: elliptic.P521()},
			want: OutcomeDenied, mention: "maxSize",
		},
		{"RSA is refused", "example-private", "ClusterIssuer", 720, csrSpec{dns: []string{apiHost}, rsaBits: 2048}, OutcomeDenied, "algorithm"},
		{"too long a life", "example-private", "ClusterIssuer", 4000, csrSpec{dns: []string{apiHost}}, OutcomeDenied, "maxDuration"},
		{
			name: "a subject organisation nobody named", issuer: "example-private", kind: "ClusterIssuer", hours: 720,
			spec: csrSpec{dns: []string{apiHost}, org: []string{"Example B.V."}},
			want: OutcomeDenied, mention: "subject.organizations",
		},
		{"a SAN otherName", "example-private", "ClusterIssuer", 720, csrSpec{dns: []string{apiHost}, otherName: true}, OutcomeDenied, "otherName"},
		{
			name: "a SPIFFE URI on a policy-approved issuer", issuer: "example-private", kind: "ClusterIssuer", hours: 720,
			spec: csrSpec{dns: []string{apiHost}, uris: []string{spiffeURI}},
			want: OutcomeDenied, mention: "uris",
		},
		{"origin needs P-384", "example-origin", "ClusterIssuer", 720, csrSpec{dns: []string{"www.example.com"}}, OutcomeApproved, ""},
		{"origin refuses P-256", "example-origin", "ClusterIssuer", 720, csrSpec{dns: []string{"www.example.com"}, curve: p256}, OutcomeDenied, "minSize"},
		{
			name: "origin lifetime ceiling is tighter", issuer: "example-origin", kind: "ClusterIssuer", hours: 2000,
			spec: csrSpec{dns: []string{"www.example.com"}},
			want: OutcomeDenied, mention: "maxDuration",
		},
		{"origin apex", "example-origin", "ClusterIssuer", 720, csrSpec{dns: []string{"example.com"}}, OutcomeApproved, ""},
		{"an issuer no policy names", "example-unknown", "ClusterIssuer", 720, csrSpec{dns: []string{"x.example.com"}}, OutcomeUnprocessed, ""},
		{"the identity issuer is skipped, never evaluated", "example-identity", "ClusterIssuer", 1, csrSpec{uris: []string{spiffeURI}}, OutcomeSkipped, ""},
		{
			name: "a namespaced Issuer, any shape: allow-all", issuer: "per-run-ca", kind: "Issuer", hours: 0,
			spec: csrSpec{cn: "ca", org: []string{"Example B.V."}, country: []string{"NL"}, uris: []string{"https://example.com/"}},
			want: OutcomeApproved, mention: "namespaced-issuers",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cr := makeCR(t, c.issuer, c.kind, c.hours, c.spec)
			res := Review(context.Background(), nil, policies, cr, opts)
			assert.Equal(t, c.want, res.Outcome, res.Detail)
			assert.Contains(t, res.Detail, c.mention)
		})
	}
}

// The chart renders no policy for the identity issuer, so without the
// skip list a request against it is Unprocessed: approver-policy would
// never approve it either, which is exactly what must stay true.
func TestIdentityIssuerIsNeverApprovedByAPolicy(t *testing.T) {
	policies := loadChartPolicies(t)
	cr := makeCR(t, "example-identity", "ClusterIssuer", 1, csrSpec{uris: []string{spiffeURI}})

	res := Review(context.Background(), nil, policies, cr, Options{})
	assert.Equal(t, OutcomeUnprocessed, res.Outcome)
	assert.True(t, res.Failed())
}

func TestSignerName(t *testing.T) {
	signer := func(ref cmmeta.IssuerReference) string {
		return SignerName(&cmapi.CertificateRequest{Spec: cmapi.CertificateRequestSpec{IssuerRef: ref}})
	}
	assert.Equal(t, "clusterissuers.cert-manager.io/a", signer(cmmeta.IssuerReference{Name: "a", Kind: "ClusterIssuer"}))
	// cert-manager defaults an empty kind to Issuer and an empty group to cert-manager.io.
	assert.Equal(t, "issuers.cert-manager.io/a", signer(cmmeta.IssuerReference{Name: "a"}))
}

func TestRBACBindingIsAskedOfTheAPIServer(t *testing.T) {
	policies := loadChartPolicies(t)

	for _, allowed := range []bool{true, false} {
		client := fake.NewSimpleClientset()
		var asked []authzv1.ResourceAttributes
		client.PrependReactor("create", "subjectaccessreviews", func(action clienttesting.Action) (bool, runtime.Object, error) {
			sar := action.(clienttesting.CreateAction).GetObject().(*authzv1.SubjectAccessReview)
			asked = append(asked, *sar.Spec.ResourceAttributes)
			sar.Status.Allowed = allowed
			return true, sar, nil
		})

		cr := makeCR(t, "example-private", "ClusterIssuer", 720, csrSpec{dns: []string{apiHost}})
		cr.Spec.Username = "system:serviceaccount:cert-manager:cert-manager"

		res := Review(context.Background(), client, policies, cr, Options{RequireRBAC: true})

		require.Len(t, asked, 1, "only the policy whose selector matched is asked about")
		assert.Equal(t, "use", asked[0].Verb)
		assert.Equal(t, "example-private", asked[0].Name)
		assert.Equal(t, "certificaterequestpolicies", asked[0].Resource)
		if allowed {
			assert.Equal(t, OutcomeApproved, res.Outcome, res.Detail)
		} else {
			assert.Equal(t, OutcomeUnprocessed, res.Outcome)
			assert.Contains(t, res.Detail, "RBAC-bound")
		}
	}

	// Without a client the RBAC half cannot be answered: an error, not a pass.
	cr := makeCR(t, "example-private", "ClusterIssuer", 720, csrSpec{dns: []string{apiHost}})
	res := Review(context.Background(), nil, policies, cr, Options{RequireRBAC: true})
	assert.Equal(t, OutcomeError, res.Outcome)
}

func TestNamespaceLabelSelectorReadsTheNamespace(t *testing.T) {
	key := "example.com/allowed"
	policy := policyapi.CertificateRequestPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "labelled"},
		Spec: policyapi.CertificateRequestPolicySpec{
			Allowed: &policyapi.CertificateRequestPolicyAllowed{
				DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"*"}},
			},
			Selector: policyapi.CertificateRequestPolicySelector{
				Namespace: &policyapi.CertificateRequestPolicySelectorNamespace{MatchLabels: map[string]string{key: "true"}},
			},
		},
	}
	policies := []policyapi.CertificateRequestPolicy{policy}
	require.True(t, HasNamespaceLabelSelector(policies))
	require.False(t, HasNamespaceLabelSelector(loadChartPolicies(t)))

	cr := makeCR(t, "example-private", "ClusterIssuer", 0, csrSpec{dns: []string{"a.example.com"}})
	// a policy with no privateKey/duration constraints and a wide allowed.dnsNames

	labelled := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app", Labels: map[string]string{key: "true"}}})
	assert.Equal(t, OutcomeApproved, Review(context.Background(), labelled, policies, cr, Options{}).Outcome)

	bare := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app"}})
	assert.Equal(t, OutcomeUnprocessed, Review(context.Background(), bare, policies, cr, Options{}).Outcome)

	assert.Equal(t, OutcomeError, Review(context.Background(), nil, policies, cr, Options{}).Outcome)
}

// A policy field the port does not evaluate must never be a silent pass.
func TestUnsupportedPolicyFieldsFailClosed(t *testing.T) {
	cel := policyapi.CertificateRequestPolicyAllowedStringSlice{
		Values:      &[]string{"*"},
		Validations: []policyapi.ValidationRule{{Rule: "true"}},
	}
	for name, allowed := range map[string]*policyapi.CertificateRequestPolicyAllowed{
		"otherNames":      {OtherNames: []policyapi.CertificateRequestPolicyAllowedOtherName{{OID: "1.2.3.4"}}},
		"cel validations": {DNSNames: &cel},
		"otherAttributes": {Subject: &policyapi.CertificateRequestPolicyAllowedX509Subject{
			OtherAttributes: []policyapi.CertificateRequestPolicyAllowedSubjectOtherAttribute{{OID: "1.2.3.4"}},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			policies := []policyapi.CertificateRequestPolicy{{
				ObjectMeta: metav1.ObjectMeta{Name: "p"},
				Spec:       policyapi.CertificateRequestPolicySpec{Allowed: allowed},
			}}
			cr := makeCR(t, "x", "ClusterIssuer", 0, csrSpec{dns: []string{"a.example.com"}})
			res := Review(context.Background(), nil, policies, cr, Options{})
			assert.Equal(t, OutcomeError, res.Outcome)
			assert.Contains(t, res.Detail, "does not evaluate")
		})
	}
}

func TestLoadCertificateRequestsReadsAListAndBareObjects(t *testing.T) {
	cr := makeCR(t, "example-private", "ClusterIssuer", 720, csrSpec{dns: []string{apiHost}})
	req := string(mustB64(cr.Spec.Request))
	body := "apiVersion: cert-manager.io/v1\nkind: CertificateRequest\nmetadata: {name: one, namespace: a}\n" +
		"spec:\n  request: " + req + "\n  issuerRef: {name: example-private, kind: ClusterIssuer}\n"
	dir := t.TempDir()

	bare := filepath.Join(dir, "bare.yaml")
	require.NoError(t, os.WriteFile(bare, []byte(body+"---\n"+body), 0o600))
	got, err := LoadCertificateRequests(bare)
	require.NoError(t, err)
	assert.Len(t, got, 2)

	list := filepath.Join(dir, "list.json")
	item := `{"apiVersion":"cert-manager.io/v1","kind":"CertificateRequest","metadata":{"name":"one","namespace":"a"},` +
		`"spec":{"request":"` + req + `","issuerRef":{"name":"example-private"}}}`
	require.NoError(t, os.WriteFile(list, []byte(`{"apiVersion":"v1","kind":"List","items":[`+item+`]}`), 0o600))
	got, err = LoadCertificateRequests(list)
	require.NoError(t, err)
	assert.Len(t, got, 1)
	assert.Equal(t, cr.Spec.Request, got[0].Spec.Request)

	empty := filepath.Join(dir, "empty.yaml")
	require.NoError(t, os.WriteFile(empty, []byte("kind: ConfigMap\napiVersion: v1\n"), 0o600))
	_, err = LoadCertificateRequests(empty)
	require.Error(t, err)
	_, err = LoadPolicies(empty)
	require.Error(t, err)
}

func TestWildcardMatches(t *testing.T) {
	for _, c := range []struct {
		pattern, str string
		want         bool
	}{
		{"*", "anything", true},
		{"", "", true},
		{"", "x", false},
		{"*.devel.example.internal", "gateway.devel.example.internal", true},
		{"*.devel.example.internal", "devel.example.internal", false},
		{"*.svc.cluster.local", "db-rw.app.svc.cluster.local", true},
		{"https://example.com/", "https://example.com/", true},
		{"https://example.com/", "https://evil.example/", false},
		{"a*b*c", "aXbYc", true},
		{"a*b*c", "aXbY", false},
	} {
		assert.Equal(t, c.want, wildcardMatches(c.pattern, c.str), "%q ~ %q", c.pattern, c.str)
	}
}

func TestBlanketApproverOff(t *testing.T) {
	for _, c := range []struct {
		name string
		args []string
		off  bool
	}{
		{"no flag: the default set, approver on", []string{"--v=2"}, false},
		{"the documented flag", []string{"--controllers=*,-certificaterequests-approver"}, true},
		{"with other exclusions", []string{"--controllers=*,-gateway-shim,-certificaterequests-approver"}, true},
		{"another controller excluded only", []string{"--controllers=*,-gateway-shim"}, false},
		{"an explicit list without it", []string{"--controllers=issuers,certificates"}, true},
		{"an explicit list with it", []string{"--controllers=issuers,certificaterequests-approver"}, false},
		{"star alone", []string{"--controllers=*"}, false},
	} {
		assert.Equal(t, c.off, BlanketApproverOff(c.args), c.name)
	}
}

func TestCheckBlanketApproverOff(t *testing.T) {
	deploy := func(name string, args ...string) *appsv1.Deployment {
		return &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "cert-manager", Labels: map[string]string{
				"app.kubernetes.io/name": "cert-manager", "app.kubernetes.io/component": "controller",
			}},
			Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "c", Args: args}},
			}}},
		}
	}
	ctx := context.Background()

	require.NoError(t, CheckBlanketApproverOff(ctx, fake.NewSimpleClientset(deploy("cm", "--controllers=*,-certificaterequests-approver")), "cert-manager"))

	err := CheckBlanketApproverOff(ctx, fake.NewSimpleClientset(deploy("cm", "--v=2")), "cert-manager")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "still runs")

	// Checking nothing must not pass.
	err = CheckBlanketApproverOff(ctx, fake.NewSimpleClientset(), "cert-manager")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no cert-manager controller")
}

func mustB64(pemBytes []byte) []byte {
	// A CertificateRequest's spec.request is base64 in YAML/JSON.
	return []byte(base64.StdEncoding.EncodeToString(pemBytes))
}
