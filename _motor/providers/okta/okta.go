package okta

import (
	"context"

	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/cnquery/motor/providers"
	"go.mondoo.com/cnquery/motor/vault"
)

var (
	_ providers.Instance           = (*Provider)(nil)
	_ providers.PlatformIdentifier = (*Provider)(nil)
)

func New(pCfg *providers.Config) (*Provider, error) {
	if pCfg.Backend != providers.ProviderType_OKTA {
		return nil, providers.ErrProviderTypeDoesNotMatch
	}

	if pCfg.Options == nil || pCfg.Options["organization"] == "" {
		return nil, errors.New("okta provider requires an organization id. please set option `organization`")
	}

	org := pCfg.Options["organization"]

	// if a secret was provided, it always overrides the env variable since it has precedence
	var token string
	if len(pCfg.Credentials) > 0 {
		log.Info().Int("credentials", len(pCfg.Credentials)).Msg("credentials")
		for i := range pCfg.Credentials {
			cred := pCfg.Credentials[i]
			if cred.Type == vault.CredentialType_password {
				token = string(cred.Secret)
			} else {
				log.Warn().Str("credential-type", cred.Type.String()).Msg("unsupported credential type for Okta provider")
			}
		}
	}

	if token == "" {
		return nil, errors.New("a valid Okta token is required, pass --token '<yourtoken>' or set OKTA_CLIENT_TOKEN environment variable")
	}

	_, client, err := okta.NewClient(
		context.Background(),
		okta.WithOrgUrl("https://"+org),
		okta.WithToken(token),
	)
	if err != nil {
		return nil, err
	}

	p := &Provider{
		organization: org,
		client:       client,
		token:        token,
	}

	return p, nil
}

type Provider struct {
	organization string
	client       *okta.Client
	token        string
}

func (t *Provider) Close() {}

func (t *Provider) Capabilities() providers.Capabilities {
	return providers.Capabilities{}
}

func (t *Provider) Kind() providers.Kind {
	return providers.Kind_KIND_API
}

func (t *Provider) Runtime() string {
	return providers.RUNTIME_OKTA
}

func (t *Provider) PlatformIdDetectors() []providers.PlatformIdDetector {
	return []providers.PlatformIdDetector{
		providers.TransportPlatformIdentifierDetector,
	}
}

func (t *Provider) Identifier() (string, error) {
	settings, _, err := t.client.OrgSetting.GetOrgSettings(context.Background())
	if err != nil {
		return "", errors.Wrap(err, "failed to get Okta org ID")
	}

	return settings.Id, nil
}

func (p *Provider) OrganizationID() string {
	return p.organization
}

func (p *Provider) Client() *okta.Client {
	return p.client
}

func (p *Provider) Token() string {
	return p.token
}
