// Package image embeds the declarative Incus/cloud-init builder configuration
// so an installed agentbox CLI can build the image without locating sources.
package image

import _ "embed"

//go:embed agentbox.yaml
var Definition []byte
