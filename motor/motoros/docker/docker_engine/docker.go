package docker_engine

import (
	"context"
	"errors"

	"github.com/docker/docker/client"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.io/mondoo/motor/motoros/capabilities"
	"go.mondoo.io/mondoo/motor/motoros/types"
	"go.mondoo.io/mondoo/motor/runtime"
	"go.mondoo.io/mondoo/nexus/assets"
)

func New(container string) (types.Transport, error) {
	dockerClient, err := GetDockerClient()
	if err != nil {
		return nil, err
	}

	// check if we are having container
	data, err := dockerClient.ContainerInspect(context.Background(), container)
	if err != nil {
		return nil, errors.New("cannot find container " + container)
	}

	if !data.State.Running {
		return nil, errors.New("container " + data.ID + " is not running")
	}

	return &Transport{
		dockerClient: dockerClient,
		container:    container,
	}, nil
}

type Transport struct {
	dockerClient *client.Client
	container    string
	Fs           *FS
}

func (t *Transport) RunCommand(command string) (*types.Command, error) {
	log.Debug().Str("command", command).Msg("docker> run command")
	c := &Command{dockerClient: t.dockerClient, Container: t.container}
	res, err := c.Exec(command)
	return res, err
}

func (t *Transport) FS() afero.Fs {
	if t.Fs == nil {
		t.Fs = &FS{
			dockerClient: t.dockerClient,
			Container:    t.container,
			Transport:    t,
		}
	}
	return t.Fs
}

func (t *Transport) FileInfo(path string) (types.FileInfoDetails, error) {
	fs := t.FS()
	afs := &afero.Afero{Fs: fs}
	stat, err := afs.Stat(path)
	if err != nil {
		return types.FileInfoDetails{}, err
	}

	uid := int64(-1)
	gid := int64(-1)
	mode := stat.Mode()

	return types.FileInfoDetails{
		Mode: types.FileModeDetails{mode},
		Size: stat.Size(),
		Uid:  uid,
		Gid:  gid,
	}, nil
}

func (t *Transport) Close() {
	t.dockerClient.Close()
}

func (t *Transport) Capabilities() capabilities.Capabilities {
	return capabilities.Capabilities{
		capabilities.RunCommand,
		capabilities.File,
	}
}

func (t *Transport) Kind() assets.Kind {
	return assets.Kind_KIND_CONTAINER
}

func (t *Transport) Runtime() string {
	return runtime.RUNTIME_DOCKER_CONTAINER
}

func GetDockerClient() (*client.Client, error) {
	cli, err := client.NewEnvClient()
	if err != nil {
		return nil, err
	}
	cli.NegotiateAPIVersion(context.Background())
	return cli, nil
}
