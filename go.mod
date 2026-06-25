module github.com/AiKeyLabs/aikey-proxy

go 1.26.1

require (
	github.com/AiKeyLabs/aikey-auth-broker v0.0.0
	github.com/AiKeyLabs/aikey-config-tool v0.0.0-00010101000000-000000000000
	github.com/AiKeyLabs/pkg/aikeycompat v0.0.0
	github.com/AiKeyLabs/pkg/aikeytime v0.0.0
	github.com/AiKeyLabs/pkg/buildinfo v0.0.0
	github.com/AiKeyLabs/pkg/providerroutes v0.0.0
	github.com/AiKeyLabs/pkg/seatassign v0.0.0
	github.com/AiKeyLabs/pkg/usagehash v0.0.0
	github.com/aikeylabs/ai-degrade-detector/proxy-plugin/rhythm v0.0.0
	github.com/cespare/xxhash/v2 v2.3.0
	github.com/imroc/req/v3 v3.57.0
	github.com/tidwall/gjson v1.19.0
	github.com/tidwall/sjson v1.2.5
	golang.org/x/crypto v0.49.0
	golang.org/x/term v0.41.0
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.48.2
)

replace github.com/AiKeyLabs/pkg/buildinfo => ../pkg/buildinfo

replace github.com/AiKeyLabs/pkg/aikeytime => ../pkg/aikeytime

replace github.com/AiKeyLabs/pkg/aikeycompat => ../pkg/aikeycompat

replace github.com/AiKeyLabs/pkg/providerroutes => ../pkg/providerroutes

replace github.com/AiKeyLabs/pkg/seatassign => ../pkg/seatassign

replace github.com/AiKeyLabs/pkg/usagehash => ../pkg/usagehash

replace github.com/AiKeyLabs/aikey-auth-broker => ../aikey-auth-broker

replace github.com/AiKeyLabs/aikey-config-tool => ../aikey-config-tool

// Phase 4 M2 first-party observer: the degrade-detector rhythm plugin
// is a separate Go module living side-by-side in the aikeylabs/ workspace.
// CI / release pipelines pin to a tagged version + drop this replace; local
// development uses the path replace so changes propagate without publish.
replace github.com/aikeylabs/ai-degrade-detector/proxy-plugin/rhythm => ../ai-degrade-detector/proxy-plugin/rhythm

require (
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/icholy/digest v1.1.0 // indirect
	github.com/klauspost/compress v1.18.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.57.1 // indirect
	github.com/refraction-networking/utls v1.8.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	modernc.org/libc v1.70.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
