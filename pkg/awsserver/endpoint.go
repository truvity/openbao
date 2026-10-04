package awsserver

import (
	"errors"
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/route53"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// DefaultEndpointTTL is the CNAME's TTL when EndpointRecordArgs.TTL is 0.
const DefaultEndpointTTL = 60

// EndpointRecordArgs configures NewEndpointRecord.
type EndpointRecordArgs struct {
	// Name is the Pulumi logical name of the record.
	Name string
	// ZoneID is the hosted zone, Record the record's DNS name and Target
	// the load balancer's DNS name it points at.
	ZoneID string
	Record string
	Target string
	// TTL defaults to DefaultEndpointTTL.
	TTL int
	// Provider is optional: empty uses the default provider.
	Provider pulumi.ProviderResource
}

// NewEndpointRecord registers the server's endpoint as a CNAME to its load
// balancer. It is its own function because the load balancer is created by
// another control plane, so a caller registers it only once that exists.
func NewEndpointRecord(ctx *pulumi.Context, args EndpointRecordArgs, options ...Option) (*route53.Record, error) {
	if args.Name == "" || args.ZoneID == "" || args.Record == "" || args.Target == "" {
		return nil, errors.New("awsserver: endpoint record: Name, ZoneID, Record and Target are required")
	}

	ttl := args.TTL
	if ttl == 0 {
		ttl = DefaultEndpointTTL
	}

	var base []pulumi.ResourceOption
	if args.Provider != nil {
		base = append(base, pulumi.Provider(args.Provider))
	}

	rec, err := route53.NewRecord(ctx, args.Name, &route53.RecordArgs{
		ZoneId:  pulumi.String(args.ZoneID),
		Name:    pulumi.String(args.Record),
		Type:    pulumi.String("CNAME"),
		Ttl:     pulumi.Int(ttl),
		Records: pulumi.StringArray{pulumi.String(args.Target)},
	}, newSettings(options).opts(KindRoute53Record, args.Name, base...)...)
	if err != nil {
		return nil, fmt.Errorf("awsserver: endpoint record %s: %w", args.Record, err)
	}

	return rec, nil
}
