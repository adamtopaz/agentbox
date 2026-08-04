package domain

import (
	"encoding/base64"
	"fmt"
	"strings"
)

type Resolver interface{ Resolve(string) ([]byte, bool) }

type Template struct{ parts []templatePart }
type templatePart struct{ literal, secret, basicUser string }

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
			parts = append(parts, templatePart{secret: name})
		case strings.HasPrefix(token, "basic:"):
			fields := strings.Split(token, ":")
			if len(fields) != 3 || !basicUserRE.MatchString(fields[1]) || !ValidKeyName(fields[2]) {
				return Template{}, fmt.Errorf("invalid basic template %q (want {basic:user:key})", token)
			}
			parts = append(parts, templatePart{basicUser: fields[1], secret: fields[2]})
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
		if p.secret != "" && !seen[p.secret] {
			seen[p.secret] = true
			out = append(out, p.secret)
		}
	}
	return out
}

func (t Template) Render(r Resolver) (string, error) {
	var b strings.Builder
	for _, p := range t.parts {
		if p.secret == "" {
			b.WriteString(p.literal)
			continue
		}
		value, ok := r.Resolve(p.secret)
		if !ok {
			return "", fmt.Errorf("secret %q is not installed", p.secret)
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
