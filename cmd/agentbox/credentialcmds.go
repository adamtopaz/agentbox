package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"agentbox/internal/control"
	"agentbox/internal/domain"
	"agentbox/internal/githubapp"
)

func cmdCredential(ctx context.Context, client *control.Client, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: agentbox credential source|grant ...")
	}
	switch args[0] {
	case "source":
		return cmdCredentialSource(ctx, client, args[1:])
	case "grant":
		return cmdCredentialGrant(ctx, client, args[1:])
	default:
		return fmt.Errorf("unknown credential command %q", args[0])
	}
}

func cmdCredentialSource(ctx context.Context, client *control.Client, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: agentbox credential source list|put|github-app|delete")
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("credential source list", flag.ContinueOnError)
		asJSON := fs.Bool("json", false, "emit JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("usage: agentbox credential source list [--json]")
		}
		sources, err := client.CredentialSources(ctx)
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(sources)
		}
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tPROVIDER\tSECRET KEYS")
		for _, source := range sources {
			fmt.Fprintf(w, "%s\t%s\t%d\n", source.Name, source.Provider, len(source.Secrets))
		}
		return w.Flush()
	case "put":
		if len(args) != 2 {
			return errors.New("usage: agentbox credential source put <source.json|->")
		}
		var source domain.CredentialSource
		if err := readJSON(args[1], &source); err != nil {
			return err
		}
		if err := domain.ValidateCredentialSource(source); err != nil {
			return err
		}
		return client.PutCredentialSource(ctx, source)
	case "github-app":
		fs := flag.NewFlagSet("credential source github-app", flag.ContinueOnError)
		clientID := fs.String("client-id", "", "GitHub App client ID")
		installationID := fs.Uint64("installation-id", 0, "GitHub App installation ID")
		privateKey := fs.String("private-key", "", "encrypted key name containing the App PEM")
		repositories := fs.String("repositories", "", "comma-separated repository names")
		repositoryIDs := fs.String("repository-ids", "", "comma-separated numeric repository IDs")
		permissions := fs.String("permissions", "", "comma-separated permission=read|write values")
		var sourceName string
		flagArgs := args[1:]
		if len(flagArgs) != 0 && !strings.HasPrefix(flagArgs[0], "-") {
			sourceName = flagArgs[0]
			flagArgs = flagArgs[1:]
		}
		if err := fs.Parse(flagArgs); err != nil {
			return err
		}
		if sourceName == "" && fs.NArg() == 1 {
			sourceName = fs.Arg(0)
		} else if fs.NArg() != 0 {
			return errors.New("usage: agentbox credential source github-app <name> --client-id ID --installation-id ID --private-key KEY [--repositories a,b | --repository-ids 1,2] [--permissions contents=write,pull_requests=write]")
		}
		if sourceName == "" || *clientID == "" || *installationID == 0 || *privateKey == "" {
			return errors.New("usage: agentbox credential source github-app <name> --client-id ID --installation-id ID --private-key KEY [--repositories a,b | --repository-ids 1,2] [--permissions contents=write,pull_requests=write]")
		}
		parameters := map[string]string{
			"client-id": *clientID, "installation-id": strconv.FormatUint(*installationID, 10),
		}
		for name, value := range map[string]string{"repositories": *repositories, "repository-ids": *repositoryIDs, "permissions": *permissions} {
			if value != "" {
				parameters[name] = value
			}
		}
		source := domain.CredentialSource{
			Name: sourceName, Provider: githubapp.ProviderName, Parameters: parameters,
			Secrets: map[string]string{githubapp.PrivateKeyRole: *privateKey},
		}
		if err := domain.ValidateCredentialSource(source); err != nil {
			return err
		}
		if _, err := githubapp.ParseConfig(source); err != nil {
			return err
		}
		return client.PutCredentialSource(ctx, source)
	case "delete":
		if len(args) != 2 {
			return errors.New("usage: agentbox credential source delete <name>")
		}
		return client.DeleteCredentialSource(ctx, args[1])
	default:
		return fmt.Errorf("unknown credential source command %q", args[0])
	}
}

func cmdCredentialGrant(ctx context.Context, client *control.Client, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: agentbox credential grant list|set|delete")
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("credential grant list", flag.ContinueOnError)
		asJSON := fs.Bool("json", false, "emit JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("usage: agentbox credential grant list [--json]")
		}
		grants, err := client.CredentialGrants(ctx)
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(grants)
		}
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "CONTAINER\tCREDENTIAL\tSOURCE")
		for _, grant := range grants {
			fmt.Fprintf(w, "%s\t%s\t%s\n", grant.Container, grant.Credential, grant.Source)
		}
		return w.Flush()
	case "set":
		if len(args) != 4 {
			return errors.New("usage: agentbox credential grant set <container> <credential> <source>")
		}
		grant := domain.CredentialGrant{Container: args[1], Credential: args[2], Source: args[3]}
		if err := domain.ValidateCredentialGrant(grant); err != nil {
			return err
		}
		return client.PutCredentialGrant(ctx, grant)
	case "delete":
		if len(args) != 3 {
			return errors.New("usage: agentbox credential grant delete <container> <credential>")
		}
		return client.DeleteCredentialGrant(ctx, args[1], args[2])
	default:
		return fmt.Errorf("unknown credential grant command %q", args[0])
	}
}
