package k8s

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.io/mondoo/motor/transports/k8s/resources"
)

func TestManifestDeployment(t *testing.T) {
	manifestFile := "./resources/testdata/appsv1.deployment.yaml"
	transport := newManifestTransport(WithManifestFile(manifestFile))
	require.NotNil(t, transport)
	res, err := transport.Resources("deployment", "centos")
	require.NoError(t, err)
	assert.Equal(t, "centos", res.Name)
	assert.Equal(t, "deployment", res.Kind)
	assert.Equal(t, 1, len(res.Resources))
}

func TestManifestInmemory(t *testing.T) {
	manifestFile := "./resources/testdata/appsv1.deployment.yaml"
	data, err := os.ReadFile(manifestFile)
	require.NoError(t, err)

	objects, err := resources.ResourcesFromManifest(bytes.NewReader(data))
	require.NoError(t, err)

	transport := newManifestTransport(WithRuntimeObjects(objects))
	require.NotNil(t, transport)
	res, err := transport.Resources("deployment", "centos")
	require.NoError(t, err)
	assert.Equal(t, "centos", res.Name)
	assert.Equal(t, "deployment", res.Kind)
	assert.Equal(t, 1, len(res.Resources))
}

func TestManifestPod(t *testing.T) {
	manifestFile := "./resources/testdata/appsv1.pod.yaml"
	transport := newManifestTransport(WithManifestFile(manifestFile))
	require.NotNil(t, transport)

	namespaces, err := transport.Namespaces()
	require.NoError(t, err)
	assert.Equal(t, 1, len(namespaces))

	pods, err := transport.Pods(namespaces[0])
	require.NoError(t, err)
	assert.Equal(t, 1, len(pods))
}