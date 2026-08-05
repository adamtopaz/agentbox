package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"

	"agentbox/internal/control"
	"agentbox/internal/domain"
	"agentbox/internal/profile"
)

func cmdStatus(ctx context.Context, client *control.Client, args []string) error {
	if len(args) != 0 {
		return errors.New("usage: agentbox status")
	}
	health, err := client.Health(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("agentboxd: %s (%d routes, %d keys, %d containers, %d credential sources, %d credential grants)\n",
		health.Status, health.Routes, health.Keys, health.Containers, health.CredentialSources, health.CredentialGrants)
	return nil
}

func cmdRoute(ctx context.Context, client *control.Client, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: agentbox route list|put|replace|delete")
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("route list", flag.ContinueOnError)
		asJSON := fs.Bool("json", false, "emit JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("usage: agentbox route list [--json]")
		}
		routes, err := client.Routes(ctx)
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(routes)
		}
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tSCOPE\tMATCH\tUPSTREAM\tMATERIAL")
		for _, route := range routes {
			match := route.Match.PathPrefix
			if route.Match.Host != "" {
				match = "host:" + route.Match.Host
			}
			keys, _ := domain.ReferencedKeys([]domain.Route{route})
			credentials, _ := domain.ReferencedCredentials([]domain.Route{route})
			var material []string
			for _, key := range keys {
				material = append(material, "secret:"+key)
			}
			for _, credential := range credentials {
				material = append(material, "credential:"+credential)
			}
			materialList := strings.Join(material, ",")
			if materialList == "" {
				materialList = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", route.Name, route.Scope, match, route.Upstream, materialList)
		}
		return w.Flush()
	case "put":
		if len(args) != 2 {
			return errors.New("usage: agentbox route put <route.json|->")
		}
		var route domain.Route
		if err := readJSON(args[1], &route); err != nil {
			return err
		}
		if err := domain.ValidateRoute(route); err != nil {
			return err
		}
		return client.PutRoute(ctx, route)
	case "replace":
		if len(args) != 2 {
			return errors.New("usage: agentbox route replace <routes.json|->")
		}
		var routes []domain.Route
		if err := readJSON(args[1], &routes); err != nil {
			return err
		}
		state := domain.NewState()
		state.Routes = routes
		if err := domain.ValidateState(state); err != nil {
			return err
		}
		return client.ReplaceRoutes(ctx, routes)
	case "delete":
		if len(args) != 2 {
			return errors.New("usage: agentbox route delete <name>")
		}
		return client.DeleteRoute(ctx, args[1])
	default:
		return fmt.Errorf("unknown route command %q", args[0])
	}
}

func cmdKey(ctx context.Context, client *control.Client, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: agentbox key list|set|delete")
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return errors.New("usage: agentbox key list")
		}
		keys, err := client.Keys(ctx)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tUPDATED")
		for _, key := range keys {
			fmt.Fprintf(w, "%s\t%s\n", key.Name, key.UpdatedAt.Local().Format("2006-01-02 15:04:05"))
		}
		return w.Flush()
	case "set":
		if len(args) != 2 {
			return errors.New("usage: agentbox key set <name>")
		}
		value, err := readSecret(args[1])
		if err != nil {
			return err
		}
		defer clearBytes(value)
		return client.SetKey(ctx, args[1], value)
	case "delete":
		if len(args) != 2 {
			return errors.New("usage: agentbox key delete <name>")
		}
		return client.DeleteKey(ctx, args[1])
	default:
		return fmt.Errorf("unknown key command %q", args[0])
	}
}

func cmdProfile(ctx context.Context, client *control.Client, args []string) error {
	if len(args) < 2 || args[0] != "apply" {
		return errors.New("usage: agentbox profile apply github|cloudflare")
	}
	existing, err := client.Routes(ctx)
	if err != nil {
		return err
	}
	var merged []domain.Route
	switch args[1] {
	case "github":
		if len(args) != 2 {
			return errors.New("usage: agentbox profile apply github")
		}
		merged = profile.ReplaceOwned(existing, profile.GitHubRoutes(), profile.OwnsGitHub)
	case "cloudflare":
		fs := flag.NewFlagSet("profile apply cloudflare", flag.ContinueOnError)
		account := fs.String("account-id", "", "Cloudflare account ID")
		gateways := fs.String("gateways", "", "comma-separated gateway names")
		privateKey := fs.String("private-key", "", "encrypted key name containing the Cloudflare API token")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || *account == "" || *gateways == "" || *privateKey == "" {
			return errors.New("usage: agentbox profile apply cloudflare --account-id ID --gateways prod,test --private-key KEY")
		}
		generated, err := profile.CloudflareRoutes(*account, splitComma(*gateways), *privateKey)
		if err != nil {
			return err
		}
		merged = profile.ReplaceOwned(existing, generated, profile.OwnsCloudflare)
	default:
		return fmt.Errorf("unknown profile %q", args[1])
	}
	if err := client.ReplaceRoutes(ctx, merged); err != nil {
		return err
	}
	fmt.Printf("applied %s profile (%d total routes)\n", args[1], len(merged))
	return nil
}

func readJSON(path string, dst any) error {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}
func printJSON(value any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}
func splitComma(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

const maxSecretBytes = 64 << 10

func readSecret(name string) ([]byte, error) {
	info, err := os.Stdin.Stat()
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		value, err := io.ReadAll(io.LimitReader(os.Stdin, maxSecretBytes+1))
		if err != nil {
			return nil, err
		}
		if len(value) > maxSecretBytes {
			return nil, fmt.Errorf("key exceeds %d bytes", maxSecretBytes)
		}
		value = bytes.TrimSuffix(value, []byte("\n"))
		value = bytes.TrimSuffix(value, []byte("\r"))
		return value, nil
	}
	fmt.Fprintf(os.Stderr, "value for %s (input hidden): ", name)
	value, err := readNoEcho(os.Stdin)
	fmt.Fprintln(os.Stderr)
	return value, err
}

func readNoEcho(file *os.File) ([]byte, error) {
	fd := int(file.Fd())
	var old syscall.Termios
	if err := ioctlTermios(fd, tcGets, &old); err != nil {
		return nil, fmt.Errorf("cannot read terminal settings: %w; pipe the value instead", err)
	}
	next := old
	next.Lflag &^= syscall.ECHO
	if err := ioctlTermios(fd, tcSets, &next); err != nil {
		return nil, fmt.Errorf("cannot disable terminal echo: %w", err)
	}
	defer ioctlTermios(fd, tcSets, &old)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGTSTP, syscall.SIGHUP)
	defer signal.Stop(signals)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case received := <-signals:
			_ = ioctlTermios(fd, tcSets, &old)
			signal.Stop(signals)
			signal.Reset(received)
			if process, err := os.FindProcess(os.Getpid()); err == nil {
				_ = process.Signal(received)
			}
		case <-done:
		}
	}()
	var out []byte
	one := make([]byte, 1)
	for {
		n, err := file.Read(one)
		if n > 0 {
			if one[0] == '\n' {
				break
			}
			out = append(out, one[0])
			if len(out) > maxSecretBytes {
				return nil, fmt.Errorf("key exceeds %d bytes", maxSecretBytes)
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}
	return out, nil
}
func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
