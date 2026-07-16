// Command aikey-proxy is the open-source data-plane proxy entrypoint.
//
// The runnable body lives in package app so a SEPARATE enterprise binary
// (github.com/AiKeyLabs/aikey-egress-proxy) can compose the same app with the
// mihomo multi-protocol egress engine WITHOUT this open-source module ever
// referencing mihomo (GPL-3.0). This binary links only the built-in socks5
// egress engine — GPL-free. See 20260716-多协议出口代理-嵌mihomo库-技术方案.md.
package main

import "github.com/AiKeyLabs/aikey-proxy/app"

func main() { app.Run() }
