# `oidf-box`

Common pieces to implement [acme-openid-federation][acmeopenid] in Pebble (issuer/server) and Lego
(requestor/client). Also implements necessary bits and pieces of [OpenID Federation][oidf].

## Demo issuances

This project contains a few issuance demos represented as integration tests, defined in
`test/integration_test.go`. These tests create small OpenID Federation federations which include an
ACME CA and one or more ACME clients. All of these run in-process, but listen for HTTP messages on
different TCP ports.

To run issuances, simply do `go test ./...` from the root of the project. Add `-v` if you want to
see what's going on. To exercise new issuance scenarios, add new tests to
`test/integration_test.go`.

## Forked dependencies

To make all this work, we had to teach various open source components about the new OpenID
Federation entity types and/or the new ACME challenge type.

The ACME CA is implemented by [our fork of Pebble][pebble-oidf] ([upstream][pebble]).

The ACME clients are implemented by [our fork of Lego][lego-oidf] ([upstream][lego]).

Besides implementing the extra features needed for the new challenge type, the forks' `go.mod` and
`go.sum` files are modified to point to each other. If you want to hack on this, you'll likely want
to edit the `replace` directives in each `go.mod` to point to your working copies.

This is tested on Linux and will probably work all right on anything Unix-y enough, or even Windows.

[oidf]: https://openid.net/specs/openid-federation-1_0-41.html
[oidf-41]: https://openid.net/specs/openid-federation-1_0-41.html
[acmeopenid]: https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html
[go-oidfed]: https://github.com/zachmann/go-oidfed
[pebble-oidf]: https://github.com/abetterinternet/pebble
[pebble]: https://github.com/letsencrypt/pebble
[lego-oidf]: https://github.com/abetterinternet/lego
[lego]: https://github.com/go-acme/lego
[acmeopenid-0573f04]: https://github.com/peppelinux/draft-demarco-acme-openid-federation/commit/0573f04f6a1fe50b01358abc3288dfff32a33c6c
