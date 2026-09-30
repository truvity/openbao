package approvercheck

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
)

// certificateRequestGVR is cert-manager's own CertificateRequest resource,
// listed through a dynamic client so this package depends on cert-manager's
// public API types alone, not its generated clientset.
var certificateRequestGVR = schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificaterequests"}

// LoadPolicies reads every CertificateRequestPolicy document from a
// multi-document YAML/JSON stream, ignoring every other kind (a rendered
// chart also carries the ClusterRole/ClusterRoleBinding this tool doesn't
// need).
func LoadPolicies(path string) ([]policyapi.CertificateRequestPolicy, error) {
	objs, err := DecodeDocuments(path)
	if err != nil {
		return nil, err
	}

	var policies []policyapi.CertificateRequestPolicy
	for _, obj := range objs {
		if obj.GetKind() != "CertificateRequestPolicy" {
			continue
		}
		var policy policyapi.CertificateRequestPolicy
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &policy); err != nil {
			return nil, fmt.Errorf("decode CertificateRequestPolicy %s: %w", obj.GetName(), err)
		}
		policies = append(policies, policy)
	}

	if len(policies) == 0 {
		return nil, fmt.Errorf("%s: %s", path, noPolicies)
	}

	return policies, nil
}

// LoadPolicyFiles reads the policies of several files and returns them in
// order: the usual shape of a set that is rendered in pieces (a chart's
// policies plus a hand-written one). A file with no policy in it is
// tolerated as long as some file has one, since a piece may render empty
// on a cluster that does not need it; no policy anywhere is an error. With
// exactly one path it is LoadPolicies, error message included.
func LoadPolicyFiles(paths ...string) ([]policyapi.CertificateRequestPolicy, error) {
	if len(paths) == 1 {
		return LoadPolicies(paths[0])
	}

	var all []policyapi.CertificateRequestPolicy
	for _, path := range paths {
		policies, err := LoadPolicies(path)
		if err != nil {
			if strings.HasSuffix(err.Error(), noPolicies) {
				continue
			}
			return nil, err
		}
		all = append(all, policies...)
	}

	if len(all) == 0 {
		return nil, fmt.Errorf("%s: %s", strings.Join(paths, ", "), noPolicies)
	}

	return all, nil
}

const noPolicies = "no CertificateRequestPolicy documents found"

// LoadCertificateRequests reads a CertificateRequestList (as `kubectl get
// certificaterequests -A -o yaml` produces) or a bare multi-document stream
// of CertificateRequest objects.
func LoadCertificateRequests(path string) ([]cmapi.CertificateRequest, error) {
	objs, err := DecodeDocuments(path)
	if err != nil {
		return nil, err
	}

	var requests []cmapi.CertificateRequest
	for _, obj := range objs {
		switch obj.GetKind() {
		case "CertificateRequestList", "List":
			// "List" is kubectl's generic wrapper (`kubectl get ... -A -o
			// json` across a single resource type): same items shape as
			// CertificateRequestList, just an untyped kind.
			items, found, err := unstructured.NestedSlice(obj.Object, "items")
			if err != nil {
				return nil, fmt.Errorf("decode CertificateRequestList: %w", err)
			}
			if !found {
				continue
			}
			for _, item := range items {
				m, ok := item.(map[string]interface{})
				if !ok {
					return nil, errors.New("decode CertificateRequestList: item is not an object")
				}
				var cr cmapi.CertificateRequest
				if err := runtime.DefaultUnstructuredConverter.FromUnstructured(m, &cr); err != nil {
					return nil, fmt.Errorf("decode CertificateRequest: %w", err)
				}
				requests = append(requests, cr)
			}
		case "CertificateRequest":
			var cr cmapi.CertificateRequest
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &cr); err != nil {
				return nil, fmt.Errorf("decode CertificateRequest %s: %w", obj.GetName(), err)
			}
			requests = append(requests, cr)
		}
	}

	if len(requests) == 0 {
		return nil, fmt.Errorf("%s: no CertificateRequest documents found", path)
	}

	return requests, nil
}

// ListLiveCertificateRequests lists every CertificateRequest in the
// cluster the dynamic client points at.
func ListLiveCertificateRequests(ctx context.Context, dynClient dynamic.Interface) ([]cmapi.CertificateRequest, error) {
	list, err := dynClient.Resource(certificateRequestGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list certificaterequests.cert-manager.io: %w", err)
	}

	var requests []cmapi.CertificateRequest
	for i := range list.Items {
		var cr cmapi.CertificateRequest
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(list.Items[i].Object, &cr); err != nil {
			return nil, fmt.Errorf("decode CertificateRequest %s/%s: %w", list.Items[i].GetNamespace(), list.Items[i].GetName(), err)
		}
		requests = append(requests, cr)
	}

	return requests, nil
}

// HasNamespaceLabelSelector reports whether any policy selects on
// namespace labels, which needs a live client to read them.
func HasNamespaceLabelSelector(policies []policyapi.CertificateRequestPolicy) bool {
	for i := range policies {
		if s := policies[i].Spec.Selector.Namespace; s != nil && s.MatchLabels != nil {
			return true
		}
	}
	return false
}

// DecodeDocuments reads every object of a multi-document YAML/JSON file.
func DecodeDocuments(path string) ([]*unstructured.Unstructured, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	decoder := kyaml.NewYAMLOrJSONDecoder(f, 4096)

	var objs []*unstructured.Unstructured
	for {
		var raw map[string]interface{}
		if err := decoder.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if len(raw) == 0 {
			continue
		}
		objs = append(objs, &unstructured.Unstructured{Object: raw})
	}

	return objs, nil
}
