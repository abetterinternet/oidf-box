module github.com/tgeoghegan/oidf-box

go 1.23.5

require (
	github.com/go-errors/errors v1.5.1
	github.com/go-jose/go-jose/v4 v4.0.5
)

require (
	github.com/letsencrypt/challtestsrv v1.3.2 // indirect
	github.com/letsencrypt/pebble/v2 v2.7.0
)

require (
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/go-acme/lego/v4 v4.23.1
	github.com/miekg/dns v1.1.64 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/mod v0.23.0 // indirect
	golang.org/x/net v0.37.0 // indirect
	golang.org/x/sync v0.12.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	golang.org/x/tools v0.30.0 // indirect
)

replace github.com/go-acme/lego/v4 => ../lego

replace github.com/letsencrypt/pebble/v2 => ../pebble
