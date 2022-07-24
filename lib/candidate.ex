defmodule ExIce.Candidate do
  @doc """
  ICE candidate representation. 
  """

  @type type() :: :host | :srflx | :prflx

  @type t() :: %__MODULE__{
          address: :inet.ip_address(),
          base_address: :inet.ip_address(),
          base_port: :inet.port_number(),
          port: :inet.port_number(),
          priority: integer(),
          socket: :inet.socket(),
          type: :host | :srflx | :prflx
        }

  defstruct [
    :address,
    :base_address,
    :base_port,
    :port,
    :priority,
    :socket,
    :type
  ]

  @spec new(
          type(),
          :inet.ip_address(),
          :inet.port_number(),
          :inet.ip_address(),
          :inet.port_number(),
          integer(),
          :inet.socket()
        ) :: t()
  def new(type, address, port, base_address, base_port, priority, socket) do
    %__MODULE__{
      address: address,
      base_address: base_address,
      base_port: base_port,
      port: port,
      priority: priority,
      socket: socket,
      type: type
    }
  end
end
