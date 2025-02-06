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
- Run Pebble: `cd $WORKSPACE/pebble && go run ./cmd/pebble -config ./test/config/pebble-config.json`
- Run Lego: `cd $WORKSPACE/lego && go run ./cmd/openidfeddemo/`

The repositories MUST be laid out relative to each other as spelled out above becuase `go.mod` in
Lego and Pebble have been modified to look for `oidf-box` at a relative path. This is tested on
Linux and will probably work all right on anything Unix-y enough, or even Windows.

[oidf]: https://openid.net/specs/openid-federation-1_0-41.html#section-7
[acmeopenid]: https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html
[timg-pebble]: https://github.com/tgeoghegan/pebble
[timg-lego]: https://github.com/tgeoghegan/lego
