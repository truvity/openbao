package approvercheck

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// evaluateAllowed ports pkg/internal/approver/allowed's Evaluate (v0.28.0)
// for commonName, dnsNames, uris, ipAddresses, emailAddresses, isCA,
// usages and the named subject.* fields. Not ported as POLICY fields:
// allowed.otherNames, allowed.subject.otherAttributes and CEL validations
// -- the policies the chart renders never set them, and unsupportedAllowedFields refuses
// (rather than silently ignores) a policy that starts using one. The
// REQUEST side of those two is ported fail-closed: a CSR carrying a SAN
// otherName (or directoryName, x400Address, ediPartyName, registeredID) or
// a subject attribute outside the named ones is a violation, exactly as
// upstream denies it when the policy lists no matching OID.
//
// subject.* was first left unported "because no policy sets it" -- but
// upstream DENIES a request whose O=/C= the policy does not name, so the
// tool passed eudi's CAs and leaves (O=Truvity B.V., C=NL) that
// approver-policy itself would have refused.
//
// Returns the violations found (nil means the request satisfies every
// allowed field in this policy), or an error if the policy uses a field
// this port does not evaluate, or the CSR can't be parsed.
func evaluateAllowed(policy *policyapi.CertificateRequestPolicy, cr *cmapi.CertificateRequest) ([]string, error) {
	if err := unsupportedAllowedFields(policy); err != nil {
		return nil, err
	}

	allowed := policy.Spec.Allowed
	if allowed == nil {
		allowed = &policyapi.CertificateRequestPolicyAllowed{}
	}

	csr, err := decodeCSR(cr.Spec.Request)
	if err != nil {
		return nil, err
	}

	var violations []string
	violations = append(violations, evaluateString("commonName", csr.Subject.CommonName, allowed.CommonName)...)
	violations = append(violations, evaluateSlice("dnsNames", csr.DNSNames, allowed.DNSNames)...)
	violations = append(violations, evaluateSlice("ipAddresses", ipStrings(csr.IPAddresses), allowed.IPAddresses)...)
	violations = append(violations, evaluateSlice("uris", uriStrings(csr.URIs), allowed.URIs)...)
	violations = append(violations, evaluateSlice("emailAddresses", csr.EmailAddresses, allowed.EmailAddresses)...)
	violations = append(violations, evaluateBool(cr.Spec.IsCA, allowed.IsCA)...)
	violations = append(violations, evaluateUsages(cr.Spec.Usages, allowed.Usages)...)
	violations = append(violations, evaluateSubject(csr, allowed.Subject)...)

	sanViolations, err := evaluateSANOtherNames(csr)
	if err != nil {
		return nil, err
	}
	violations = append(violations, sanViolations...)

	return violations, nil
}

// unsupportedAllowedFields refuses (fail closed, as an error rather than a
// silent pass) a policy that sets any allowed field this port does not
// evaluate.
func unsupportedAllowedFields(policy *policyapi.CertificateRequestPolicy) error {
	allowed := policy.Spec.Allowed
	if allowed == nil {
		return nil
	}
	if allowed.Subject != nil && len(allowed.Subject.OtherAttributes) > 0 {
		return fmt.Errorf("policy %q sets allowed.subject.otherAttributes, which this tool does not evaluate", policy.Name)
	}
	if allowed.Subject != nil && allowed.Subject.SerialNumber != nil && len(allowed.Subject.SerialNumber.Validations) > 0 {
		return fmt.Errorf("policy %q uses a CEL validation, which this tool does not evaluate", policy.Name)
	}
	if len(allowed.OtherNames) > 0 {
		return fmt.Errorf("policy %q sets allowed.otherNames, which this tool does not evaluate", policy.Name)
	}
	if allowed.CommonName != nil && len(allowed.CommonName.Validations) > 0 {
		return fmt.Errorf("policy %q uses a CEL validation, which this tool does not evaluate", policy.Name)
	}
	fields := []*policyapi.CertificateRequestPolicyAllowedStringSlice{allowed.DNSNames, allowed.IPAddresses, allowed.URIs, allowed.EmailAddresses}
	if sub := allowed.Subject; sub != nil {
		fields = append(fields, sub.Organizations, sub.Countries, sub.OrganizationalUnits, sub.Localities, sub.Provinces, sub.StreetAddresses, sub.PostalCodes)
	}
	for _, s := range fields {
		if s != nil && len(s.Validations) > 0 {
			return fmt.Errorf("policy %q uses a CEL validation, which this tool does not evaluate", policy.Name)
		}
	}
	return nil
}

func evaluateString(field, value string, crp *policyapi.CertificateRequestPolicyAllowedString) []string {
	if value == "" {
		if crp != nil && crp.Required != nil && *crp.Required {
			return []string{fmt.Sprintf("%s: required but absent from the request", field)}
		}
		return nil
	}

	if crp == nil || crp.Value == nil {
		return []string{fmt.Sprintf("%s: %q is set on the request but the policy allows no value", field, value)}
	}

	if !wildcardMatches(*crp.Value, value) {
		return []string{fmt.Sprintf("%s: %q does not match allowed pattern %q", field, value, *crp.Value)}
	}

	return nil
}

func evaluateSlice(field string, values []string, crp *policyapi.CertificateRequestPolicyAllowedStringSlice) []string {
	if len(values) == 0 {
		if crp != nil && crp.Required != nil && *crp.Required {
			return []string{fmt.Sprintf("%s: required but absent from the request", field)}
		}
		return nil
	}

	if crp == nil || crp.Values == nil {
		return []string{fmt.Sprintf("%s: %s is set on the request but the policy allows no values", field, strings.Join(values, ","))}
	}

	if !wildcardSubset(*crp.Values, values) {
		return []string{fmt.Sprintf("%s: %s is not a subset of allowed values %s", field, strings.Join(values, ","), strings.Join(*crp.Values, ","))}
	}

	return nil
}

func evaluateBool(isCA bool, crp *bool) []string {
	if !isCA {
		return nil
	}
	if crp == nil || !*crp {
		return []string{"isCA: request sets isCA=true but the policy does not allow it"}
	}
	return nil
}

// evaluateUsages mirrors allowed/evaluator.go's Usages(): a request with NO
// usages is never denied on this field, whatever the policy says. A
// request WITH usages needs allowed.usages set and every requested usage
// to be a wildcard-subset of it.
func evaluateUsages(requested []cmapi.KeyUsage, allowed *[]cmapi.KeyUsage) []string {
	if len(requested) == 0 {
		return nil
	}

	var req []string
	for _, u := range requested {
		req = append(req, string(u))
	}

	if allowed == nil {
		return []string{fmt.Sprintf("usages: %s is set on the request but the policy allows none", strings.Join(req, ","))}
	}

	var pol []string
	for _, u := range *allowed {
		pol = append(pol, string(u))
	}

	if !wildcardSubset(pol, req) {
		return []string{fmt.Sprintf("usages: %s is not a subset of allowed usages %s", strings.Join(req, ","), strings.Join(pol, ","))}
	}

	return nil
}

func ipStrings(ips []net.IP) []string {
	var out []string
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func uriStrings(uris []*url.URL) []string {
	var out []string
	for _, u := range uris {
		out = append(out, u.String())
	}
	return out
}

// Subject attribute OIDs that have a named allowed.commonName or
// allowed.subject.* field upstream (allowed/evaluator.go's
// namedSubjectOIDs). Any other attribute needs allowed.subject.
// otherAttributes, which the chart's policies never set -- so it is always a
// violation here, as upstream reports "no allowed values".
var namedSubjectOIDs = []asn1.ObjectIdentifier{
	{2, 5, 4, 3},  // commonName
	{2, 5, 4, 5},  // serialNumber
	{2, 5, 4, 6},  // country
	{2, 5, 4, 7},  // locality
	{2, 5, 4, 8},  // province
	{2, 5, 4, 9},  // streetAddress
	{2, 5, 4, 10}, // organization
	{2, 5, 4, 11}, // organizationalUnit
	{2, 5, 4, 17}, // postalCode
}

// evaluateSubject mirrors upstream's subjectEvaluator: a nil
// allowed.subject is treated as an empty one, so ANY organization,
// country, ... on the request is a violation unless the policy names it.
// Like upstream it reads the named fields from the parsed pkix.Name.
func evaluateSubject(csr *x509.CertificateRequest, allowed *policyapi.CertificateRequestPolicyAllowedX509Subject) []string {
	if allowed == nil {
		allowed = &policyapi.CertificateRequestPolicyAllowedX509Subject{}
	}
	sub := csr.Subject

	var violations []string
	violations = append(violations, evaluateSlice("subject.organizations", sub.Organization, allowed.Organizations)...)
	violations = append(violations, evaluateSlice("subject.countries", sub.Country, allowed.Countries)...)
	violations = append(violations, evaluateSlice("subject.organizationalUnits", sub.OrganizationalUnit, allowed.OrganizationalUnits)...)
	violations = append(violations, evaluateSlice("subject.localities", sub.Locality, allowed.Localities)...)
	violations = append(violations, evaluateSlice("subject.provinces", sub.Province, allowed.Provinces)...)
	violations = append(violations, evaluateSlice("subject.streetAddresses", sub.StreetAddress, allowed.StreetAddresses)...)
	violations = append(violations, evaluateSlice("subject.postalCodes", sub.PostalCode, allowed.PostalCodes)...)
	violations = append(violations, evaluateString("subject.serialNumber", sub.SerialNumber, allowed.SerialNumber)...)

	for _, atv := range sub.Names {
		if slices.ContainsFunc(namedSubjectOIDs, atv.Type.Equal) {
			continue
		}
		violations = append(violations, fmt.Sprintf("subject.otherAttributes[%s]: set on the request but the policy allows no values", atv.Type))
	}

	return violations
}

// evaluateSANOtherNames mirrors upstream's OtherNames evaluator for the
// case every policy the chart renders is in (no allowed.otherNames): any SAN
// GeneralName that crypto/x509 does not surface as a DNS name, email, URI
// or IP -- otherName [0], x400Address [3], directoryName [4],
// ediPartyName [5], registeredID [8] -- is a violation. cert-manager copies
// the raw SAN extension into the issued certificate, so upstream refuses
// these, and a tool reading only csr.DNSNames etc. would not see them.
func evaluateSANOtherNames(csr *x509.CertificateRequest) ([]string, error) {
	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	names := map[int]string{0: "otherName", 3: "x400Address", 4: "directoryName", 5: "ediPartyName", 8: "registeredID"}

	var violations []string
	for _, ext := range csr.Extensions {
		if !ext.Id.Equal(sanOID) {
			continue
		}
		var seq asn1.RawValue
		if rest, err := asn1.Unmarshal(ext.Value, &seq); err != nil || len(rest) > 0 || !seq.IsCompound {
			return nil, fmt.Errorf("subjectAltName extension could not be decoded")
		}
		for rest := seq.Bytes; len(rest) > 0; {
			var gn asn1.RawValue
			var err error
			if rest, err = asn1.Unmarshal(rest, &gn); err != nil {
				return nil, fmt.Errorf("subjectAltName entry could not be decoded: %w", err)
			}
			if name, ok := names[gn.Tag]; ok && gn.Class == asn1.ClassContextSpecific {
				violations = append(violations, fmt.Sprintf("subjectAltName.%s: set on the request but the policy allows none", name))
			}
		}
	}
	return violations, nil
}
