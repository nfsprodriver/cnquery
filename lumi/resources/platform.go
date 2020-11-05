package resources

import (
	"errors"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.io/mondoo/lumi"
	"go.mondoo.io/mondoo/vadvisor/api"
	"go.mondoo.io/mondoo/vadvisor/sources/eol"
)

func (s *lumiPlatform) init(args *lumi.Args) (*lumi.Args, Platform, error) {
	platform, err := s.Runtime.Motor.Platform()
	if err == nil {
		(*args)["name"] = platform.Name
		(*args)["title"] = platform.Title
		(*args)["arch"] = platform.Arch
		(*args)["release"] = platform.Release
		(*args)["kind"] = platform.Kind.Name()
		(*args)["runtimeEnv"] = platform.Runtime

		families := []interface{}{}
		for _, f := range platform.Family {
			families = append(families, f)
		}
		(*args)["family"] = families

	} else {
		log.Error().Err(err).Msg("could not determine platform")
	}
	return args, nil, nil
}

func (s *lumiPlatform) id() (string, error) {
	return "platform", nil
}

func (s *lumiPlatformEol) id() (string, error) {
	return "platform.eol", nil
}

func (p *lumiPlatformEol) init(args *lumi.Args) (*lumi.Args, PlatformEol, error) {
	obj, err := p.Runtime.CreateResource("platform")
	if err != nil {
		return nil, nil, err
	}

	platform := obj.(Platform)

	name, _ := platform.Name()
	release, _ := platform.Release()
	arch, _ := platform.Arch()

	platformEolInfo := eol.IsEol(&api.Platform{
		Name:    name,
		Release: release,
		Arch:    arch,
	})

	if platformEolInfo == nil {
		return nil, nil, errors.New("no platform eol information available")
	}

	eolDate, err := time.Parse(time.RFC3339, platformEolInfo.EolDate)
	if err != nil {
		return nil, nil, err
	}

	// if the package cannot be found, we init it as an empty package
	(*args)["docsUrl"] = platformEolInfo.DocsUrl
	(*args)["productUrl"] = platformEolInfo.ProductUrl
	(*args)["date"] = &eolDate

	return args, nil, nil
}
