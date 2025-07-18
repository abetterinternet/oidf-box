module github.com/abetterinternet/oidf-box

go 1.24

toolchain go1.24.3

require (
	github.com/go-acme/lego/v4 v4.23.1
	github.com/go-errors/errors v1.5.1
	github.com/go-jose/go-jose/v4 v4.1.0
	github.com/lestrrat-go/jwx/v3 v3.0.1
	github.com/letsencrypt/pebble/v2 v2.7.0
	github.com/zachmann/go-oidfed v0.3.2-0.20250602062824-fda2357fd2a7
)

require (
	github.com/TwiN/gocache/v2 v2.2.2 // indirect
	github.com/adam-hanna/arrayOperations v1.0.1 // indirect
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/dgraph-io/badger/v4 v4.7.0 // indirect
	github.com/dgraph-io/ristretto/v2 v2.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fatih/structs v1.1.0 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-resty/resty/v2 v2.16.5 // indirect
	github.com/goccy/go-json v0.10.4 // indirect
	github.com/gofiber/fiber/v2 v2.52.8 // indirect
	github.com/google/flatbuffers v25.2.10+incompatible // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jarcoal/httpmock v1.4.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/lestrrat-go/blackmagic v1.0.3 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.0-beta2 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/letsencrypt/challtestsrv v1.3.2 // indirect
	github.com/lithammer/fuzzysearch v1.1.8 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/miekg/dns v1.1.64 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/redis/go-redis/v9 v9.9.0 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/scylladb/go-set v1.0.3-0.20200225121959-cc7b2070d91e // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.51.0 // indirect
	github.com/valyala/tcplisten v1.0.0 // indirect
	github.com/vmihailenco/msgpack/v5 v5.4.1 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/otel v1.35.0 // indirect
	go.opentelemetry.io/otel/metric v1.35.0 // indirect
	go.opentelemetry.io/otel/trace v1.35.0 // indirect
	golang.org/x/crypto v0.38.0 // indirect
	golang.org/x/exp v0.0.0-20241210194714-1829a127f884 // indirect
	golang.org/x/mod v0.24.0 // indirect
	golang.org/x/net v0.40.0 // indirect
	golang.org/x/sync v0.14.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.25.0 // indirect
	golang.org/x/tools v0.33.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	tideland.dev/go/slices v0.2.0 // indirect
)

replace github.com/go-acme/lego/v4 v4.23.1 => github.com/abetterinternet/lego-oidf/v4 v4.0.0-20250715210113-4b4cd040e089

replace github.com/letsencrypt/pebble/v2 v2.7.0 => github.com/abetterinternet/pebble-oidf/v2 v2.0.0-20250715210126-627f522c7f94
