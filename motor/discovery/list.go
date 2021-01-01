package discovery

import (
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/rs/zerolog/log"
	"go.mondoo.io/mondoo/motor/asset"
	"go.mondoo.io/mondoo/motor/discovery/aws"
	"go.mondoo.io/mondoo/motor/discovery/gcp"
	"go.mondoo.io/mondoo/motor/transports"
	"go.mondoo.io/mondoo/stringx"
)

type Plugin interface {
	Name() string
	List() ([]*asset.Asset, error)
}

func ListAssets(runtimes ...string) ([]*asset.Asset, error) {
	askRuntimes := []Plugin{}

	if stringx.Contains(runtimes, transports.RUNTIME_AWS_EC2) ||
		stringx.Contains(runtimes, transports.RUNTIME_AWS_SSM_MANAGED) ||
		stringx.Contains(runtimes, transports.RUNTIME_AWS_ECR) {
		cfg, err := external.LoadDefaultAWSConfig()
		if err != nil {
			log.Warn().Err(err).Msg("skip aws assets")
		} else {
			if stringx.Contains(runtimes, transports.RUNTIME_AWS_EC2) {
				plugin_aws, err := aws.NewEc2Discovery(cfg)
				if err == nil {
					askRuntimes = append(askRuntimes, plugin_aws)
				}
			}

			if stringx.Contains(runtimes, transports.RUNTIME_AWS_SSM_MANAGED) {
				plugin_aws, err := aws.NewSSMManagedInstancesDiscovery(cfg)
				if err == nil {
					askRuntimes = append(askRuntimes, plugin_aws)
				}
			}

			if stringx.Contains(runtimes, transports.RUNTIME_AWS_ECR) {
				plugin_aws, err := aws.NewEcrImages(cfg)
				if err == nil {
					askRuntimes = append(askRuntimes, plugin_aws)
				}
			}
		}
	}

	// if stringslice.Contains(runtimes, asset.RUNTIME_GCP_COMPUTE) {
	// 	askRuntimes = append(askRuntimes, gcp.NewCompute())
	// }

	if stringx.Contains(runtimes, transports.RUNTIME_GCP_GCR) {
		askRuntimes = append(askRuntimes, gcp.NewGCRImages())
	}

	// if stringslice.Contains(runtimes, transports.RUNTIME_DOCKER_CONTAINER) {
	// 	askRuntimes = append(askRuntimes, &docker.Container{})
	// }

	// if stringslice.Contains(runtimes, transports.RUNTIME_DOCKER_IMAGE) {
	// 	askRuntimes = append(askRuntimes, &docker.Images{})
	// }

	// if stringslice.Contains(runtimes, transports.RUNTIME_DOCKER_REGISTRY) {
	// 	askRuntimes = append(askRuntimes, &docker.DockerRegistryImages{})
	// }

	discoveredAssets := []*asset.Asset{}
	for i := range askRuntimes {
		plugin := askRuntimes[i]
		pluginAssets, err := plugin.List()
		if err == nil {
			discoveredAssets = append(discoveredAssets, pluginAssets...)
		} else {
			log.Error().Err(err).Msgf("could not load assets from %s", plugin.Name())
		}
	}

	return discoveredAssets, nil
}
