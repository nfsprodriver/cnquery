package aws

import (
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

const (
	ImageIdLabel        string = "mondoo.app/ami-id"
	RegionLabel         string = "mondoo.app/region"
	IntegrationMrnLabel string = "mondoo.app/integration-mrn"
	SSMPingLabel        string = "mondoo.app/ssm-connection"
	InstanceLabel       string = "mondoo.app/instance"
	IPLabel             string = "mondoo.app/ip"
	DNSLabel            string = "mondoo.app/public-dns-name"
	EBSScanLabel        string = "mondoo.app/ebs-volume-scan"
)

func addAWSMetadataLabels(assetLabels map[string]string, instance basicInstanceInfo) map[string]string {
	assetLabels[RegionLabel] = instance.Region
	if instance.InstanceId != nil {
		assetLabels[InstanceLabel] = *instance.InstanceId
	}
	if instance.IPAddress != nil {
		assetLabels[IPLabel] = *instance.IPAddress
	}
	if instance.PublicDnsName != nil {
		assetLabels[DNSLabel] = *instance.PublicDnsName
	}
	if instance.ImageId != nil {
		assetLabels[ImageIdLabel] = *instance.ImageId
	}
	if instance.SSMPlatformType != "" {
		assetLabels[SsmPlatformLabel] = instance.SSMPlatformType
	}
	if instance.SSMPingStatus != "" {
		assetLabels[SSMPingLabel] = instance.SSMPingStatus
	}
	return assetLabels
}

type basicInstanceInfo struct {
	InstanceId      *string
	IPAddress       *string
	Region          string
	PublicDnsName   *string
	ImageId         *string
	SSMPingStatus   string
	SSMPlatformType string
}

func ssmInstanceToBasicInstanceInfo(instance types.InstanceInformation, region string) basicInstanceInfo {
	return basicInstanceInfo{
		InstanceId:      instance.InstanceId,
		IPAddress:       instance.IPAddress,
		Region:          region,
		SSMPingStatus:   string(instance.PingStatus),
		SSMPlatformType: string(instance.PlatformType),
	}
}

func ec2InstanceToBasicInstanceInfo(instance ec2types.Instance, region string) basicInstanceInfo {
	return basicInstanceInfo{
		InstanceId:    instance.InstanceId,
		IPAddress:     instance.PublicIpAddress,
		Region:        region,
		PublicDnsName: instance.PublicDnsName,
		ImageId:       instance.ImageId,
	}
}