package cmd

import (
	"context"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.mondoo.com/cnquery"
	"go.mondoo.com/cnquery/cli/config"
	"go.mondoo.com/cnquery/cli/sysinfo"
	"go.mondoo.com/cnquery/providers-sdk/v1/upstream"
	"go.mondoo.com/ranger-rpc"
	"go.mondoo.com/ranger-rpc/plugins/authentication/statictoken"
)

func init() {
	rootCmd.AddCommand(loginCmd)
	loginCmd.Flags().StringP("token", "t", "", "Set a client registration token.")
	loginCmd.Flags().String("name", "", "Set asset name.")
	loginCmd.Flags().String("api-endpoint", "", "Set the Mondoo API endpoint.")
}

var loginCmd = &cobra.Command{
	Use:     "login",
	Aliases: []string{"register"},
	Short:   "Register with Mondoo Platform.",
	Long: `
Log in to Mondoo Platform using a registration token. To pass in the token, use 
the '--token' flag.

You can generate a new registration token on the Mondoo Dashboard. Go to
https://console.mondoo.com -> Space -> Settings -> Registration Token. Copy the token and pass it in 
using the '--token' argument.

You remain logged in until you explicitly log out using the 'logout' subcommand.
	`,
	PreRun: func(cmd *cobra.Command, args []string) {
		viper.BindPFlag("api_endpoint", cmd.Flags().Lookup("api-endpoint"))
		viper.BindPFlag("name", cmd.Flags().Lookup("name"))
	},
	Run: func(cmd *cobra.Command, args []string) {
		token, _ := cmd.Flags().GetString("token")
		register(token)
	},
}

func register(token string) {
	var err error
	var credential *upstream.ServiceAccountCredentials

	// determine information about the client
	sysInfo, err := sysinfo.GatherSystemInfo()
	if err != nil {
		log.Fatal().Err(err).Msg("could not gather client information")
	}
	defaultPlugins := defaultRangerPlugins(sysInfo, cnquery.DefaultFeatures)

	apiEndpoint := viper.GetString("api_endpoint")
	token = strings.TrimSpace(token)

	// NOTE: login is special because we do not have a config yet
	proxy, err := config.GetAPIProxy()
	if err != nil {
		log.Fatal().Err(err).Msg("could not parse proxy URL")
	}
	httpClient := ranger.NewHttpClient(ranger.WithProxy(proxy))

	// we handle three cases here:
	// 1. user has a token provided
	// 2. user has no token provided, but has a service account file is already there
	//
	if token != "" {
		// print token details
		claims, err := upstream.ExtractTokenClaims(token)
		if err != nil {
			log.Warn().Err(err).Msg("could not read the token")
		} else {
			if len(claims.Description) > 0 {
				log.Info().Msg("token description: " + claims.Description)
			}
			if claims.IsExpired() {
				log.Warn().Msg("token is expired")
			} else {
				log.Info().Msg("token will expire at " + claims.Claims.Expiry.Time().Format(time.RFC1123))
			}

			if apiEndpoint == "" {
				apiEndpoint = claims.ApiEndpoint
			}
		}

		// gather service account
		plugins := []ranger.ClientPlugin{}
		plugins = append(plugins, defaultPlugins...)
		plugins = append(plugins, statictoken.NewRangerPlugin(token))

		client, err := upstream.NewAgentManagerClient(apiEndpoint, httpClient, plugins...)
		if err != nil {
			log.Fatal().Err(err).Msg("could not connect to mondoo platform")
		}

		name := viper.GetString("name")
		if name == "" {
			name = sysInfo.Hostname
		}

		confirmation, err := client.RegisterAgent(context.Background(), &upstream.AgentRegistrationRequest{
			Token: token,
			Name:  name,
			AgentInfo: &upstream.AgentInfo{
				Mrn:              "",
				Version:          sysInfo.Version,
				Build:            sysInfo.Build,
				PlatformName:     sysInfo.Platform.Name,
				PlatformRelease:  sysInfo.Platform.Version,
				PlatformArch:     sysInfo.Platform.Arch,
				PlatformIp:       sysInfo.IP,
				PlatformHostname: sysInfo.Hostname,
				Labels:           nil,
				PlatformId:       sysInfo.PlatformId,
			},
		})
		if err != nil {
			log.Fatal().Err(err).Msg("failed to log in client")
		}

		log.Debug().Msg("store configuration")
		// overwrite force, otherwise it will be stored
		viper.Set("force", false)

		// update configuration file, api-endpoint is set automatically
		viper.Set("agent_mrn", confirmation.AgentMrn)
		viper.Set("api_endpoint", confirmation.Credential.ApiEndpoint)
		viper.Set("space_mrn", confirmation.Credential.GetParentMrn())
		viper.Set("mrn", confirmation.Credential.Mrn)
		viper.Set("private_key", confirmation.Credential.PrivateKey)
		viper.Set("certificate", confirmation.Credential.Certificate)

		credential = confirmation.Credential
	} else {
		// try to read local options
		opts, optsErr := config.Read()
		if optsErr != nil {
			log.Fatal().Msg("could not load configuration, please use --token or --config with the appropriate values")
		}
		// print the used config to the user
		config.DisplayUsedConfig()

		httpClient, err = opts.GetHttpClient()
		if err != nil {
			log.Fatal().Err(err).Msg("could not create http client")
		}

		if opts.AgentMrn != "" {
			// already authenticated
			log.Info().Msg("client is already logged in, skipping")
			credential = opts.GetServiceCredential()
		} else {
			credential = opts.GetServiceCredential()

			// run ping pong
			plugins := []ranger.ClientPlugin{}
			plugins = append(plugins, defaultPlugins...)
			certAuth, err := upstream.NewServiceAccountRangerPlugin(credential)
			if err != nil {
				log.Warn().Err(err).Msg("could not initialize certificate authentication")
			}
			plugins = append(plugins, certAuth)

			client, err := upstream.NewAgentManagerClient(apiEndpoint, httpClient, plugins...)
			if err != nil {
				log.Fatal().Err(err).Msg("could not connect to Mondoo Platform")
			}

			name := viper.GetString("name")
			if name == "" {
				name = sysInfo.Hostname
			}

			confirmation, err := client.RegisterAgent(context.Background(), &upstream.AgentRegistrationRequest{
				Name: name,
				AgentInfo: &upstream.AgentInfo{
					Mrn:              opts.AgentMrn,
					Version:          sysInfo.Version,
					Build:            sysInfo.Build,
					PlatformName:     sysInfo.Platform.Name,
					PlatformRelease:  sysInfo.Platform.Version,
					PlatformArch:     sysInfo.Platform.Arch,
					PlatformIp:       sysInfo.IP,
					PlatformHostname: sysInfo.Hostname,
					Labels:           opts.Labels,
					PlatformId:       sysInfo.PlatformId,
				},
			})
			if err != nil {
				log.Fatal().Err(err).Msg("failed to log in client")
			}

			// update configuration file, api-endpoint is set automatically
			// NOTE: we ignore the credentials from confirmation since the service never returns the credentials again
			viper.Set("agent_mrn", confirmation.AgentMrn)
		}
	}

	err = config.StoreConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("could not write mondoo configuration")
	}

	// run ping pong to validate the service account
	plugins := []ranger.ClientPlugin{}
	plugins = append(plugins, defaultPlugins...)
	certAuth, err := upstream.NewServiceAccountRangerPlugin(credential)
	if err != nil {
		log.Warn().Err(err).Msg("could not initialize certificate authentication")
	}
	plugins = append(plugins, certAuth)
	client, err := upstream.NewAgentManagerClient(apiEndpoint, httpClient, plugins...)
	if err != nil {
		log.Fatal().Err(err).Msg("could not connect to mondoo platform")
	}

	_, err = client.PingPong(context.Background(), &upstream.Ping{})
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	log.Info().Msgf("client %s has logged in successfully", viper.Get("agent_mrn"))
}
