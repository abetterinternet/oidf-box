# `oidf-box`

Common pieces to implement [acme-openid-federation][acmeopenid] in Pebble (issuer/server) and Lego
(requestor/client). Also implements necessary bits and pieces of [OpenID Federation][oidf].

## Workspace preparation

You will need:

- Recent Go
- Choose a directory as workspace
- Clone this repository to `$WORKSPACE/oidf-box`
- Clone [my fork of go-oidfed][timg-go-oidfed] to `$WORKSPACE/go-oidfed` and check out branch
  `extra-entities`
- Clone [my fork of Pebble][timg-pebble] to `$WORKSPACE/pebble` and check out branch `openidfed`
- Clone [my fork of Lego][timg-lego] to `$WORKSPACE/lego` and check out branch `openidfed-client`

The repositories MUST be laid out relative to each other as spelled out above because the various
`go.mod`s have been modified to look for each other at relative paths.

## Do an issuance with `federation` demo

If you check out tags `checkpoint-2` of each of `oidf-box`, `tgeoghegan/pebble` and
`tgeoghegan/lego`, the demo will work in a manner conforming to draft-demarco-acme-openid-federation
commit [`0573f04`][acme-oidf] and [openid-federation-1_0-41][oidf-41]. This demo uses a homegrown
implementation of just enough of OpenID Federation to support issuance.

To run the demo and do issuance, run `federation`:

```sh
cd $WORKSPACE/oidf-box && go run ./cmd/
```

This demo and the modules in `oidf-box` that support it are likely to be deleted in the near future.

The `federation` binary will:

- create an OpenID federation consisting of a trust anchor, an intermediate, an ACME issuer and two
  ACME requestors
- serve Federation endpoints for each entity on different ports on `localhost`
- Run Pebble, configured to service OpenID Federation ACME challenges
- Run Lego to obtain a certificate for the two ACME requestor entities

The entity identifiers are hard coded to things like `http://localhost:8001`, and so this setup will
break if those ports are already bound by something else.

## `go-oidfed` demo

`cmd/go-oidfed` contains an alternate demo setup that uses `go-oidfed` to implement OpenID
Federation. `go-oidfed` is far more robust than `oidf-box`, implementing all of the standard
federation endpoints as well as advanced features like metadata policy and trust marks.

To run the demo and do issuance, run `go-oidfed`:

```sh
cd $WORKSPACE/oidf-box && go run ./cmd/go-oidfed/
```

This is tested on Linux and will probably work all right on anything Unix-y enough, or even Windows.

[oidf]: https://openid.net/specs/openid-federation-1_0-41.html
[oidf-41]: https://openid.net/specs/openid-federation-1_0-41.html
[acmeopenid]: https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html
[timg-go-oidfed]: https://github.com/tgeoghegan/go-oidfed
[timg-pebble]: https://github.com/tgeoghegan/pebble
[timg-lego]: https://github.com/tgeoghegan/lego
[acmeopenid-0573f04]: https://github.com/peppelinux/draft-demarco-acme-openid-federation/commit/0573f04f6a1fe50b01358abc3288dfff32a33c6c
