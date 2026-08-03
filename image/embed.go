// Package image embeds the container provisioning script. go:embed cannot
// reach across package directories, so the asset directory is itself a tiny
// package.
package image

import _ "embed"

//go:embed provision.sh
var Provision []byte
