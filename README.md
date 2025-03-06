# ExICE

[![Hex.pm](https://img.shields.io/hexpm/v/ex_ice.svg)](https://hex.pm/packages/ex_ice)
[![API Docs](https://img.shields.io/badge/api-docs-yellow.svg?style=flat)](https://hexdocs.pm/ex_ice)
[![CI](https://img.shields.io/github/actions/workflow/status/elixir-webrtc/ex_ice/ci.yml?logo=github&label=CI)](https://github.com/elixir-webrtc/ex_ice/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/elixir-webrtc/ex_ice/graph/badge.svg?token=E98NHC8B00)](https://codecov.io/gh/elixir-webrtc/ex_ice)

Trickle ICE implementation.

Implements:
* [RFC 8445](https://datatracker.ietf.org/doc/html/rfc8445)
* [RFC 8838](https://datatracker.ietf.org/doc/html/rfc8838)
* [ICE mDNS](https://datatracker.ietf.org/doc/html/draft-ietf-rtcweb-mdns-ice-candidates) (client side)

## Features
* compatible both with aggressive and regular nomination
* role conflict resolution
* supports host, prflx, srflx and relay candidates
* transaction pacing
* keepalives (both incoming and outgoing) on valid and selected pairs
* mDNS client

## Limitations
* there is always only one stream and one component -
we don't plan to add support for multiple streams and components
as WebRTC multiplexes traffic on a single socket but PRs are welcomed

## Installation

```elixir
def deps do
  [
    {:ex_ice, "~> 0.10.0"}
  ]
end
```

## Usage

See our [example](https://github.com/elixir-webrtc/ex_ice/tree/master/example), 
[integration tests](https://github.com/elixir-webrtc/ex_ice/blob/master/test/integration/p2p_test.exs),
and [documentation](https://hexdocs.pm/ex_ice/readme.html) for usage examples.

We also provide a very simple [signalling server](https://github.com/elixir-webrtc/ex_ice/tree/master/signalling_server), which can be used
to connect two ICE agents.


