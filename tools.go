//go:build tools
// +build tools

package tools

import (
	_ "github.com/KvalitetsIT/dtrack/pkg/dependencytrack"
	_ "github.com/vektra/mockery/v3"
	_ "golang.org/x/vuln/cmd/govulncheck"
	_ "honnef.co/go/tools/cmd/staticcheck"
	_ "mvdan.cc/gofumpt"
)
