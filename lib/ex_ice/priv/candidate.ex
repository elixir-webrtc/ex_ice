defmodule ExICE.Priv.Candidate do
  @moduledoc false

  @type type() :: :host | :srflx | :prflx | :relay

  @type t() :: struct()

  @type config :: [
          address: :inet.ip_address() | String.t(),
          port: :inet.port_number(),
          base_address: :inet.ip_address(),
          base_port: :inet.port_number(),
          socket: :inet.socket(),
          priority: integer(),
          foundation: integer(),
          transport: :udp | :tcp
        ]

  @callback new(config()) :: t()

  @callback marshal(t()) :: String.t()

  @callback family(t()) :: :ipv4 | :ipv6

  @callback to_candidate(t()) :: ExICE.Candidate.t()

  @callback send_data(t(), :inet.ip_address(), :inet.port_number(), binary()) ::
              {:ok, t()} | {:error, term(), t()}

  @spec priority(type()) :: integer()
  def priority(type) do
    type_preference =
      case type do
        :host -> 126
        :prflx -> 110
        :srflx -> 100
        :relay -> 0
      end

    # That's not fully correct as according to RFC 8445 sec. 5.1.2.1 we should:
    # * use value of 65535 when there is only one IP address
    # * use different values when there are multiple IP addresses
    local_preference = 65_535

    2 ** 24 * type_preference + 2 ** 8 * local_preference + 2 ** 0 * (256 - 1)
  end

  @spec foundation(type(), :inet.ip_address(), :inet.ip_address() | nil, atom()) :: integer()
  def foundation(type, ip, stun_turn_ip, transport) do
    {type, ip, stun_turn_ip, transport}
    |> then(&inspect(&1))
    |> then(&:erlang.crc32(&1))
  end
end
