package main

import (
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
	"go.mondoo.com/cnquery/apps/cnquery/cmd"
)

func main() {
	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	dir := flags.String("docs-path", "", "Path directory where you want to generate doc files")

	if err := flags.Parse(os.Args); err != nil {
		log.Fatal().Err(err).Msg("error: could not parse flags")
	}

	if *dir == "" {
		log.Fatal().Msg("--docs-path is required")
	}

	err := cmd.GenerateMarkdown(*dir)
	if err != nil {
		log.Fatal().Err(err).Msg("could not generate markdown")
	}
}