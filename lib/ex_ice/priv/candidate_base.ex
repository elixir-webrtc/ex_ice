defmodule ExICE.Priv.CandidateBase do
  @moduledoc false
  alias ExICE.Priv.{Candidate, Utils}

  @type t :: %__MODULE__{
          id: integer(),
          address: :inet.ip_address() | String.t(),
          base_address: :inet.ip_address() | nil,
          base_port: :inet.port_number() | nil,
          foundation: integer(),
          port: :inet.port_number(),
          priority: integer(),
          transport: :udp | :tcp,
          transport_module: module(),
          socket: :inet.socket() | nil,
          type: Candidate.type(),
          tcp_type: Candidate.tcp_type(),
          closed?: boolean()
        }

  @derive {Inspect, except: [:socket]}
  @enforce_keys [
    :id,
    :address,
    :foundation,
    :port,
    :priority,
    :transport,
    :transport_module,
    :type
  ]
  defstruct @enforce_keys ++ [:base_address, :base_port, :socket, :tcp_type, closed?: false]

  @spec new(Candidate.type(), Keyword.t()) :: t()
  def new(type, config) do
    transport_module = Keyword.fetch!(config, :transport_module)
    transport = transport_module.transport()
    address = Keyword.fetch!(config, :address)

    %__MODULE__{
      id: Utils.id(),
      address: address,
      base_address: config[:base_address],
      base_port: config[:base_port],
      foundation: Candidate.foundation(type, address, nil, transport),
      port: Keyword.fetch!(config, :port),
      priority: Keyword.fetch!(config, :priority),
      transport: transport,
      transport_module: transport_module,
      socket: Keyword.fetch!(config, :socket),
      type: type,
      tcp_type: config[:tcp_type]
    }
  end

  @spec marshal(t()) :: String.t()
  def marshal(cand), do: cand |> to_candidate() |> ExICE.Candidate.marshal()

  @spec family(t()) :: :ipv4 | :ipv6
  def family(%__MODULE__{address: {_, _, _, _}}), do: :ipv4
  def family(%__MODULE__{address: {_, _, _, _, _, _, _, _}}), do: :ipv6

  @spec tcp_type(t()) :: Candidate.tcp_type()
  def tcp_type(%__MODULE__{tcp_type: tt}), do: tt

  @spec to_candidate(t()) :: ExICE.Candidate.t()
  def to_candidate(cand) do
    ExICE.Candidate.new(cand.type,
      address: cand.address,
      port: cand.port,
      base_address: cand.base_address,
      base_port: cand.base_port,
      foundation: cand.foundation,
      transport: cand.transport,
      priority: cand.priority,
      tcp_type: cand.tcp_type
    )
  end
end
