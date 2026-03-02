defmodule ExICE.Priv.Candidate do
  @moduledoc false

  @type type :: :host | :srflx | :prflx | :relay
  @type tcp_type :: :active | :passive | :so | nil

  @type t :: struct()

  @type config :: [
          address: :inet.ip_address() | String.t(),
          port: :inet.port_number(),
          base_address: :inet.ip_address(),
          base_port: :inet.port_number(),
          socket: :inet.socket(),
          priority: integer(),
          foundation: integer(),
          transport: :udp | :tcp,
          tcp_type: tcp_type()
        ]

  @callback new(config()) :: t()

  @callback marshal(t()) :: String.t()

  @callback family(t()) :: :ipv4 | :ipv6

  @callback tcp_type(t()) :: tcp_type()

  @callback to_candidate(t()) :: ExICE.Candidate.t()

  @callback send_data(t(), :inet.ip_address(), :inet.port_number(), binary()) ::
              {:ok, t()} | {:error, term(), t()}

  @spec priority!(
          %{:inet.ip_address() => non_neg_integer()},
          :inet.ip_address(),
          type(),
          tcp_type()
        ) ::
          non_neg_integer()
  def priority!(local_preferences, base_address, type, tcp_type) do
    other_preference = Map.fetch!(local_preferences, base_address)
    do_priority(other_preference, type, tcp_type)
  end

  @spec priority(
          %{:inet.ip_address() => non_neg_integer()},
          :inet.ip_address(),
          type(),
          tcp_type()
        ) ::
          {%{:inet.ip_address() => non_neg_integer()}, non_neg_integer()}
  def priority(local_preferences, base_address, type, tcp_type) do
    other_preference =
      Map.get(local_preferences, base_address) || generate_other_preference(local_preferences)

    local_preferences = Map.put(local_preferences, base_address, other_preference)

    {local_preferences, do_priority(other_preference, type, tcp_type)}
  end

  defp do_priority(other_preference, type, tcp_type) do
    type_preference = type_preference(type, tcp_type)
    direction_preference = direction_preference(type, tcp_type)

    local_preference = 2 ** 13 * direction_preference + other_preference

    2 ** 24 * type_preference + 2 ** 8 * local_preference + 2 ** 0 * (256 - 1)
  end

  # TODO: revisit these when implementing UDP+TCP support at the same time
  # UDP
  defp type_preference(type, nil) do
    case type do
      :host -> 126
      :prflx -> 110
      :srflx -> 100
      :relay -> 10
    end
  end

  # TCP
  defp type_preference(type, _tcp_type) do
    case type do
      :host -> 80
      :prflx -> 70
      # :nat_assisted -> 65
      :srflx -> 60
      # :udp_tunneled -> 45
      :relay -> 0
    end
  end

  # UDP
  defp direction_preference(_type, nil), do: 7

  # TCP
  defp direction_preference(type, tcp_type) when type in [:host, :udp_tunneled, :relay] do
    case tcp_type do
      :active -> 6
      :passive -> 4
      :so -> 2
    end
  end

  defp direction_preference(_type, tcp_type) do
    case tcp_type do
      :so -> 6
      :active -> 4
      :passive -> 2
    end
  end

  defp generate_other_preference(local_preferences, attempts \\ 200)

  defp generate_other_preference(_local_preferences, 0),
    do: raise("Couldn't generate local preference")

  defp generate_other_preference(local_preferences, attempts) do
    # 0..8191
    <<pref::13, _::3>> = :crypto.strong_rand_bytes(2)

    if local_preferences |> Map.values() |> Enum.member?(pref) do
      generate_other_preference(local_preferences, attempts - 1)
    else
      pref
    end
  end

  @spec foundation(type(), :inet.ip_address() | String.t(), :inet.ip_address() | nil, atom()) ::
          integer()
  def foundation(type, ip, stun_turn_ip, transport) do
    {type, ip, stun_turn_ip, transport} |> inspect() |> :erlang.crc32()
  end
end
