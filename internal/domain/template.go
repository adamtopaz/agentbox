package domain

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
)

type MaterialKind string

const (
	MaterialSecret     MaterialKind = "secret"
	MaterialCredential MaterialKind = "credential"
)

type MaterialReference struct {
	Kind MaterialKind
	Name string
}

// Resolver obtains sensitive material for a request principal. Implementors
// may resolve durable secrets immediately or acquire renewable credentials.
type Resolver interface {
	Resolve(context.Context, string, MaterialReference) ([]byte, error)
}

type Template struct{ parts []templatePart }
type templatePart struct {
	literal, basicUser string
	reference          MaterialReference
}

func ParseTemplate(value string) (Template, error) {
	if value == "" {
		return Template{}, fmt.Errorf("value must not be empty")
	}
	for _, ch := range []byte(value) {
		if ch < 0x20 || ch > 0x7e {
			return Template{}, fmt.Errorf("value contains non-printable or non-ASCII byte 0x%02x", ch)
		}
	}
	var parts []templatePart
	for len(value) > 0 {
		open := strings.IndexByte(value, '{')
		if open < 0 {
			if strings.ContainsRune(value, '}') {
				return Template{}, fmt.Errorf("unmatched '}'")
			}
			parts = append(parts, templatePart{literal: value})
			break
		}
		if open > 0 {
			parts = append(parts, templatePart{literal: value[:open]})
		}
		value = value[open:]
		close := strings.IndexByte(value, '}')
		if close < 0 {
			return Template{}, fmt.Errorf("unclosed template")
		}
		token := value[1:close]
		value = value[close+1:]
		switch {
		case strings.HasPrefix(token, "secret:"):
			name := strings.TrimPrefix(token, "secret:")
			if !ValidKeyName(name) {
				return Template{}, fmt.Errorf("invalid secret reference %q", name)
			}
			parts = append(parts, templatePart{reference: MaterialReference{Kind: MaterialSecret, Name: name}})
		case strings.HasPrefix(token, "credential:"):
			name := strings.TrimPrefix(token, "credential:")
			if !ValidName(name) {
				return Template{}, fmt.Errorf("invalid credential reference %q", name)
			}
			parts = append(parts, templatePart{reference: MaterialReference{Kind: MaterialCredential, Name: name}})
		case strings.HasPrefix(token, "basic:"):
			fields := strings.Split(token, ":")
			if len(fields) == 3 && basicUserRE.MatchString(fields[1]) && ValidKeyName(fields[2]) {
				parts = append(parts, templatePart{basicUser: fields[1], reference: MaterialReference{Kind: MaterialSecret, Name: fields[2]}})
				break
			}
			if len(fields) == 4 && basicUserRE.MatchString(fields[1]) && fields[2] == string(MaterialCredential) && ValidName(fields[3]) {
				parts = append(parts, templatePart{basicUser: fields[1], reference: MaterialReference{Kind: MaterialCredential, Name: fields[3]}})
				break
			}
			return Template{}, fmt.Errorf("invalid basic template %q (want {basic:user:key} or {basic:user:credential:name})", token)
		default:
			return Template{}, fmt.Errorf("unknown template %q", token)
		}
	}
	return Template{parts: parts}, nil
}

func (t Template) Keys() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range t.parts {
		if p.reference.Kind == MaterialSecret && !seen[p.reference.Name] {
			seen[p.reference.Name] = true
			out = append(out, p.reference.Name)
		}
	}
	return out
}

func (t Template) Credentials() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range t.parts {
		if p.reference.Kind == MaterialCredential && !seen[p.reference.Name] {
			seen[p.reference.Name] = true
			out = append(out, p.reference.Name)
		}
	}
	return out
}

func (t Template) Render(ctx context.Context, principal string, r Resolver) (string, error) {
	var b strings.Builder
	for _, p := range t.parts {
		if p.reference.Kind == "" {
			b.WriteString(p.literal)
			continue
		}
		value, err := r.Resolve(ctx, principal, p.reference)
		if err != nil {
			return "", err
		}
		if p.basicUser != "" {
			raw := make([]byte, len(p.basicUser)+1+len(value))
			copy(raw, p.basicUser+":")
			copy(raw[len(p.basicUser)+1:], value)
			encoded := base64.StdEncoding.EncodeToString(raw)
			clearBytes(raw)
			b.WriteString(encoded)
		} else {
			b.Write(value)
		}
		clearBytes(value)
	}
	out := b.String()
	for _, ch := range []byte(out) {
		if ch < 0x20 || ch > 0x7e {
			return "", fmt.Errorf("rendered header contains byte 0x%02x", ch)
		}
	}
	return out, nil
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
