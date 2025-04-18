# `oidf-box`

Common pieces to implement [acme-openid-federation][acmeopenid] in Pebble (issuer/server) and Lego
(requestor/client). Also implements necessary bits and pieces of [OpenID Federation][oidf].

## Do an issuance

You will need:

- Recent Go
- Choose a directory as workspace
- Clone this repository to `$WORKSPACE/oidf-box`
- Clone [my fork of Pebble][timg-pebble] to `$WORKSPACE/pebble` and check out branch `openidfed`
- Clone [my fork of Lego][timg-lego] to `$WORKSPACE/lego` and check out branch `openidfed-client`
- Run `federation`: `cd $WORKSPACE/oidf-box && go run ./cmd/`
- Run Pebble: `cd $WORKSPACE/pebble && go run ./cmd/pebble -config ./test/config/pebble-config.json`
- Run Lego: `cd $WORKSPACE/lego && go run ./cmd/openidfeddemo/`

The repositories MUST be laid out relative to each other as spelled out above because `go.mod` in
Lego and Pebble have been modified to look for `oidf-box` at a relative path.

If you check out tags `checkpoint-1` of each of `oidf-box`, `tgeoghegan/pebble` and
`tgeoghegan/lego`, the demo will work in a manner conforming to draft-demarco-acme-openid-federation
commit [`a7fc286`][acme-oidf] and [openid-federation-1_0-41][oidf-41].

The test setup creates a variety of OpenID Federation entities that are just ports bound on
`localhost`. The entity identifiers are hard coded to things like `http://localhost:8001`, and so
this setup will break if those ports are already bound by something else.

This is tested on Linux and will probably work all right on anything Unix-y enough, or even Windows.

[oidf]: https://openid.net/specs/openid-federation-1_0-41.html
[oidf-41]: https://openid.net/specs/openid-federation-1_0-41.html
[acmeopenid]: https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html
[timg-pebble]: https://github.com/tgeoghegan/pebble
[timg-lego]: https://github.com/tgeoghegan/lego
[acmeopenid-a7fc286]: https://github.com/peppelinux/draft-demarco-acme-openid-federation/commit/a7fc286296ce5d3760486f2fb34e9f6cf5f3bd8a
