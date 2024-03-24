defmodule ExICE.CandidateBase do
  @moduledoc """
  ICE candidate representation.
  """

  alias ExICE.{Candidate, Utils}

  @type t() :: %__MODULE__{
          id: integer(),
          address: :inet.ip_address() | String.t(),
          base_address: :inet.ip_address() | nil,
          base_port: :inet.port_number() | nil,
          foundation: integer(),
          port: :inet.port_number(),
          priority: integer(),
          transport: :udp | :tcp,
          socket: :inet.socket() | nil,
          type: Candidate.type()
        }

  @derive {Inspect, except: [:socket]}
  defstruct [
    :id,
    :address,
    :base_address,
    :base_port,
    :foundation,
    :port,
    :priority,
    :transport,
    :socket,
    :type
  ]

  @spec new(Keyword.t()) :: t()
  def new(config) do
    type = Keyword.fetch!(config, :type)
    transport = Keyword.fetch!(config, :transport)
    address = Keyword.fetch!(config, :address)

    priority = config[:priority] || priority(type)

    %__MODULE__{
      id: Utils.id(),
      address: address,
      base_address: config[:base_address],
      base_port: config[:base_port],
      foundation: foundation(type, address, nil, transport),
      port: Keyword.fetch!(config, :port),
      priority: priority,
      transport: transport,
      socket: Keyword.fetch!(config, :socket),
      type: type
    }
  end

  @spec marshal(t()) :: String.t()
  def marshal(cand) do
    component_id = 1

    %__MODULE__{
      foundation: foundation,
      transport: transport,
      priority: priority,
      address: address,
      port: port,
      type: type
    } = cand

    transport = transport_to_string(transport)
    address = address_to_string(address)

    "#{foundation} #{component_id} #{transport} #{priority} #{address} #{port} typ #{type}"
  end

  @spec family(t()) :: :ipv4 | :ipv6
  def family(%__MODULE__{address: {_, _, _, _}}), do: :ipv4
  def family(%__MODULE__{address: {_, _, _, _, _, _, _, _}}), do: :ipv6

  @spec priority(Candidate.type()) :: integer()
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

  @spec receive_data(t(), :inet.ip_address(), :inet.port_number(), binary()) ::
          {:ok, t()} | {:ok, binary(), t()} | {:error, term(), t()}
  def receive_data(%__MODULE__{type: :relay} = cand, _src_ip, _src_port, _data) do
    {:error, :invalid_data, cand}
  end

  def receive_data(cand, _src_ip, _src_port, data) do
    {:ok, data, cand}
  end

  defp foundation(type, ip, stun_turn_ip, transport) do
    {type, ip, stun_turn_ip, transport}
    |> then(&inspect(&1))
    |> then(&:erlang.crc32(&1))
  end

  defp address_to_string(address), do: :inet.ntoa(address)
  defp transport_to_string(:udp), do: "UDP"
end
