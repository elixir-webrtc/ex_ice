# ExICE

[![Package](https://img.shields.io/badge/-Package-important)](https://hex.pm/packages/ex_ice) 
[![Documentation](https://img.shields.io/badge/-Documentation-blueviolet)](https://hexdocs.pm/ex_ice)
[![codecov](https://codecov.io/gh/elixir-webrtc/ex_ice/branch/master/graph/badge.svg?token=83POQD1KST)](https://codecov.io/gh/elixir-webrtc/ex_ice)

Trickle ICE implementation.

RFC implemented:
* [RFC 8445](https://datatracker.ietf.org/doc/html/rfc8445)
* [RFC 8838](https://datatracker.ietf.org/doc/html/rfc8838)

## Features
* compatible both with aggressive and regular nomination
* role conflict resolution
* supports host, prflx, srflx and remote relay candidates (support for local relay candidates is planned)
* transaction pacing
* keepalives on valid and selected pairs

## Limitations
* there is always only one stream and one component -
we don't plan to add support for multiple streams and components
as WebRTC multiplexes traffic on a single socket but PRs are welcomed

## Installation

```elixir
def deps do
  [
    {:ex_ice, "~> 0.6.1"}
  ]
end
```

## Usage

See our [example](https://github.com/elixir-webrtc/ex_ice/tree/master/example), 
[integration tests](https://github.com/elixir-webrtc/ex_ice/blob/master/test/integration/p2p_test.exs),
and [documentation](https://hexdocs.pm/ex_ice/readme.html) for usage examples.

We also provide a very simple [signalling server](https://github.com/elixir-webrtc/ex_ice/tree/master/signalling_server), which can be used
to connect two ICE agents.


