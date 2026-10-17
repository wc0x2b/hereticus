// The Go fixture: shfmt, which `fixtures/go.sh` builds with garble, as Go
// malware is obfuscated. A module of its own pins every dependency, and
// `fixtures/go/shfmt-3.11.0` holds the release before it.
module example.com/shfmt

go 1.27

require mvdan.cc/sh/v3 v3.12.0

require (
	github.com/google/renameio/v2 v2.0.0 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/term v0.32.0 // indirect
	mvdan.cc/editorconfig v0.3.0 // indirect
)
