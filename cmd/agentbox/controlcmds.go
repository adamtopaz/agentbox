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
	fmt.Printf("agentboxd: %s (%d profiles, %d routes, %d keys, %d containers, %d credential sources, %d credential bindings)\n",
		health.Status, health.Profiles, health.Routes, health.Keys, health.Containers, health.CredentialSources, health.CredentialBindings)
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
		if fs.NArg() != 1 {
			return errors.New("usage: agentbox route list [--json] <profile>")
		}
		routes, err := client.Routes(ctx, fs.Arg(0))
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(routes)
		}
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tMATCH\tUPSTREAM\tMATERIAL")
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
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", route.Name, match, route.Upstream, materialList)
		}
		return w.Flush()
	case "put":
		if len(args) != 3 {
			return errors.New("usage: agentbox route put <profile> <route.json|->")
		}
		var route domain.Route
		if err := readJSON(args[2], &route); err != nil {
			return err
		}
		if err := domain.ValidateRoute(route); err != nil {
			return err
		}
		return client.PutRoute(ctx, args[1], route)
	case "replace":
		if len(args) != 3 {
			return errors.New("usage: agentbox route replace <profile> <routes.json|->")
		}
		var routes []domain.Route
		if err := readJSON(args[2], &routes); err != nil {
			return err
		}
		for i, route := range routes {
			if err := domain.ValidateRoute(route); err != nil {
				return fmt.Errorf("route %d: %w", i, err)
			}
		}
		return client.ReplaceRoutes(ctx, args[1], routes)
	case "delete":
		if len(args) != 3 {
			return errors.New("usage: agentbox route delete <profile> <name>")
		}
		return client.DeleteRoute(ctx, args[1], args[2])
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
	if len(args) == 0 {
		return errors.New("usage: agentbox profile list|show|create|put|delete|set|unset")
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("profile list", flag.ContinueOnError)
		asJSON := fs.Bool("json", false, "emit JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("usage: agentbox profile list [--json]")
		}
		profiles, err := client.Profiles(ctx)
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(profiles)
		}
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tROUTES\tCREDENTIALS\tENVIRONMENT")
		for _, current := range profiles {
			fmt.Fprintf(w, "%s\t%d\t%d\t%d\n", current.Name, len(current.Routes), len(current.Credentials), len(current.Environment))
		}
		return w.Flush()
	case "show":
		if len(args) != 2 {
			return errors.New("usage: agentbox profile show <name>")
		}
		current, err := findProfile(ctx, client, args[1])
		if err != nil {
			return err
		}
		return printJSON(current)
	case "create":
		if len(args) != 2 {
			return errors.New("usage: agentbox profile create <name>")
		}
		profiles, err := client.Profiles(ctx)
		if err != nil {
			return err
		}
		for _, current := range profiles {
			if current.Name == args[1] {
				return fmt.Errorf("profile %q already exists", args[1])
			}
		}
		created, err := profile.New(args[1])
		if err != nil {
			return err
		}
		return client.PutProfile(ctx, created)
	case "put":
		if len(args) != 2 {
			return errors.New("usage: agentbox profile put <profile.json|->")
		}
		var current domain.Profile
		if err := readJSON(args[1], &current); err != nil {
			return err
		}
		if err := domain.ValidateProfile(current); err != nil {
			return err
		}
		return client.PutProfile(ctx, current)
	case "delete":
		if len(args) != 2 {
			return errors.New("usage: agentbox profile delete <name>")
		}
		return client.DeleteProfile(ctx, args[1])
	case "set":
		return cmdProfileSet(ctx, client, args[1:])
	case "unset":
		return cmdProfileUnset(ctx, client, args[1:])
	default:
		return fmt.Errorf("unknown profile command %q", args[0])
	}
}

func cmdProfileSet(ctx context.Context, client *control.Client, args []string) error {
	if len(args) < 2 {
		return errors.New("usage: agentbox profile set cloudflare|github <profile> [flags]")
	}
	current, err := findProfile(ctx, client, args[1])
	if err != nil {
		return err
	}
	switch args[0] {
	case "cloudflare":
		fs := flag.NewFlagSet("profile set cloudflare", flag.ContinueOnError)
		account := fs.String("account-id", "", "Cloudflare account ID")
		gateway := fs.String("gateway", "", "Cloudflare gateway name")
		privateKey := fs.String("private-key", "", "encrypted key name containing the Cloudflare AI Gateway token")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || *account == "" || *gateway == "" || *privateKey == "" {
			return errors.New("usage: agentbox profile set cloudflare <profile> --account-id ID --gateway NAME --private-key KEY")
		}
		current, err = profile.SetCloudflare(current, *account, *gateway, *privateKey)
	case "github":
		fs := flag.NewFlagSet("profile set github", flag.ContinueOnError)
		source := fs.String("source", "", "GitHub App credential source")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || *source == "" {
			return errors.New("usage: agentbox profile set github <profile> --source SOURCE")
		}
		current, err = profile.SetGitHub(current, *source)
	default:
		return fmt.Errorf("unknown profile integration %q", args[0])
	}
	if err != nil {
		return err
	}
	return client.PutProfile(ctx, current)
}

func cmdProfileUnset(ctx context.Context, client *control.Client, args []string) error {
	if len(args) != 2 {
		return errors.New("usage: agentbox profile unset cloudflare|github <profile>")
	}
	current, err := findProfile(ctx, client, args[1])
	if err != nil {
		return err
	}
	switch args[0] {
	case "cloudflare":
		current, err = profile.UnsetCloudflare(current)
	case "github":
		current, err = profile.UnsetGitHub(current)
	default:
		return fmt.Errorf("unknown profile integration %q", args[0])
	}
	if err != nil {
		return err
	}
	return client.PutProfile(ctx, current)
}

func findProfile(ctx context.Context, client *control.Client, name string) (domain.Profile, error) {
	profiles, err := client.Profiles(ctx)
	if err != nil {
		return domain.Profile{}, err
	}
	for _, current := range profiles {
		if current.Name == name {
			return current, nil
		}
	}
	return domain.Profile{}, fmt.Errorf("profile %q does not exist; create it first", name)
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
