package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"text/tabwriter"

	"agentbox/internal/control"
)

func cmdUser(ctx context.Context, client *control.Client, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: agentbox user list [USERNAME] | grant USERNAME PROFILE | revoke USERNAME PROFILE")
	}
	switch args[0] {
	case "list":
		if len(args) > 2 {
			return errors.New("usage: agentbox user list [USERNAME]")
		}
		var filter *uint32
		if len(args) == 2 {
			uid, err := lookupUID(args[1])
			if err != nil {
				return err
			}
			filter = &uid
		}
		grants, err := client.ProfileGrants(ctx)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "USER\tUID\tPROFILE")
		for _, grant := range grants {
			if filter != nil && grant.UID != *filter {
				continue
			}
			name := "-"
			if account, err := user.LookupId(strconv.FormatUint(uint64(grant.UID), 10)); err == nil {
				name = account.Username
			}
			fmt.Fprintf(w, "%s\t%d\t%s\n", name, grant.UID, grant.Profile)
		}
		return w.Flush()
	case "grant", "revoke":
		if len(args) != 3 {
			return fmt.Errorf("usage: agentbox user %s USERNAME PROFILE", args[0])
		}
		uid, err := lookupUID(args[1])
		if err != nil {
			return err
		}
		if args[0] == "grant" {
			return client.PutProfileGrant(ctx, uid, args[2])
		}
		return client.DeleteProfileGrant(ctx, uid, args[2])
	default:
		return fmt.Errorf("unknown user command %q", args[0])
	}
}

func lookupUID(name string) (uint32, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return 0, fmt.Errorf("look up user %q: %w", name, err)
	}
	value, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("user %q has invalid uid %q", name, account.Uid)
	}
	return uint32(value), nil
}
