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
          proto: :udp,
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
    :proto,
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
    proto = :udp

    %__MODULE__{
      address: address,
      base_address: base_address,
      base_port: base_port,
      foundation: foundation(type, address, nil, proto),
      port: port,
      priority: 0,
      proto: proto,
      socket: socket,
      type: type
    }
  end

  defp foundation(type, ip, stun_turn_ip, proto) do
    {type, ip, stun_turn_ip, proto}
    |> then(&inspect(&1))
    |> then(&:erlang.crc32(&1))
  end
end
