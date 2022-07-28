defmodule ExIce.Candidate do
  @doc """
  ICE candidate representation. 
  """

  @type type() :: :host | :srflx | :prflx

  @type t() :: %__MODULE__{
          address: :inet.ip_address(),
          base_address: :inet.ip_address(),
          base_port: :inet.port_number(),
          foundation: integer(),
          port: :inet.port_number(),
          priority: integer(),
          transport: :udp,
          socket: :inet.socket(),
          type: :host | :srflx | :prflx
        }

  defstruct [
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

  @spec new(
          type(),
          :inet.ip_address(),
          :inet.port_number(),
          :inet.ip_address(),
          :inet.port_number(),
          :inet.socket()
        ) :: t()
  def new(type, address, port, base_address, base_port, socket) do
    transport = :udp

    %__MODULE__{
      address: address,
      base_address: base_address,
      base_port: base_port,
      foundation: foundation(type, address, nil, transport),
      port: port,
      priority: 0,
      transport: transport,
      socket: socket,
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

  @spec unmarshal(String.t()) :: t()
  def unmarshal(_string) do
  end

  defp foundation(type, ip, stun_turn_ip, transport) do
    {type, ip, stun_turn_ip, transport}
    |> then(&inspect(&1))
    |> then(&:erlang.crc32(&1))
  end

  defp address_to_string(address), do: :inet.ntoa(address)
  defp transport_to_string(:udp), do: "UDP"
end
