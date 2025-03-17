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

  @spec priority!(%{:inet.ip_address() => non_neg_integer()}, :inet.ip_address(), type()) ::
          non_neg_integer()
  def priority!(local_preferences, base_address, type) do
    local_preference = Map.fetch!(local_preferences, base_address)
    do_priority(local_preference, type)
  end

  @spec priority(%{:inet.ip_address() => non_neg_integer()}, :inet.ip_address(), type()) ::
          {%{:inet.ip_address() => non_neg_integer()}, non_neg_integer()}
  def priority(local_preferences, base_address, type) do
    local_preference =
      Map.get(local_preferences, base_address) || generate_local_preference(local_preferences)

    local_preferences = Map.put(local_preferences, base_address, local_preference)

    {local_preferences, do_priority(local_preference, type)}
  end

  defp do_priority(local_preference, type) do
    type_preference =
      case type do
        :host -> 126
        :prflx -> 110
        :srflx -> 100
        :relay -> 0
      end

    2 ** 24 * type_preference + 2 ** 8 * local_preference + 2 ** 0 * (256 - 1)
  end

  defp generate_local_preference(local_preferences, attempts \\ 200)

  defp generate_local_preference(_local_preferences, 0),
    do: raise("Couldn't generate local preference")

  defp generate_local_preference(local_preferences, attempts) do
    # this should give us a number from 0 to 2**16-1
    <<pref::16>> = :crypto.strong_rand_bytes(2)

    if Map.has_key?(local_preferences, pref) do
      generate_local_preference(local_preferences, attempts - 1)
    else
      pref
    end
  end

  @spec foundation(type(), :inet.ip_address() | String.t(), :inet.ip_address() | nil, atom()) ::
          integer()
  def foundation(type, ip, stun_turn_ip, transport) do
    {type, ip, stun_turn_ip, transport}
    |> then(&inspect(&1))
    |> then(&:erlang.crc32(&1))
  end
end
