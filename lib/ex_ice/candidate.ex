defmodule ExICE.Candidate do
  @moduledoc """
  ICE candidate representation.
  """

  alias ExICE.Utils

  @type type() :: :host | :srflx | :prflx | :relay

  @type t() :: %__MODULE__{
          id: integer(),
          address: :inet.ip_address() | String.t(),
          base_address: :inet.ip_address() | nil,
          base_port: :inet.port_number() | nil,
          foundation: integer(),
          port: :inet.port_number(),
          priority: integer(),
          transport: :udp,
          socket: :inet.socket() | nil,
          type: type()
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

  @spec new(
          type(),
          :inet.ip_address() | String.t(),
          :inet.port_number(),
          :inet.ip_address() | nil,
          :inet.port_number() | nil,
          :inet.socket() | nil,
          priority: integer()
        ) :: t()
  def new(type, address, port, base_address, base_port, socket, opts \\ [])
      when type in [:host, :srflx, :prflx, :relay] do
    transport = :udp

    priority = opts[:priority] || priority(type)

    %__MODULE__{
      id: Utils.id(),
      address: address,
      base_address: base_address,
      base_port: base_port,
      foundation: foundation(type, address, nil, transport),
      port: port,
      priority: priority,
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

  @spec unmarshal(String.t()) :: {:ok, t()} | {:error, term()}
  def unmarshal(string) do
    with [f_str, c_str, tr_str, pr_str, a_str, po_str, "typ", ty_str] <-
           String.split(string, " ", parts: 8),
         {foundation, ""} <- Integer.parse(f_str),
         {_component_id, ""} <- Integer.parse(c_str),
         {:ok, transport} <- parse_transport(String.downcase(tr_str)),
         {priority, ""} <- Integer.parse(pr_str),
         {:ok, address} <- parse_address(a_str),
         {port, ""} <- Integer.parse(po_str),
         {:ok, type} <- parse_type(ty_str) do
      {:ok,
       %__MODULE__{
         id: Utils.id(),
         address: address,
         foundation: foundation,
         port: port,
         priority: priority,
         transport: transport,
         type: type
       }}
    else
      err when is_list(err) -> {:error, :invalid_candidate}
      err -> err
    end
  end

  @spec family(t()) :: :ipv4 | :ipv6
  def family(%__MODULE__{address: {_, _, _, _}}), do: :ipv4
  def family(%__MODULE__{address: {_, _, _, _, _, _, _, _}}), do: :ipv6

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

  defp parse_transport("udp"), do: {:ok, :udp}
  defp parse_transport(_other), do: {:error, :invalid_transport}

  defp parse_address(address) do
    if String.ends_with?(address, ".local") do
      {:ok, address}
    else
      :inet.parse_address(String.to_charlist(address))
    end
  end

  defp parse_type("host" <> _rest), do: {:ok, :host}
  defp parse_type("srflx" <> _rest), do: {:ok, :srflx}
  defp parse_type("prflx" <> _rest), do: {:ok, :prflx}
  defp parse_type("relay" <> _rest), do: {:ok, :relay}
  defp parse_type(_other), do: {:error, :invalid_type}

  defp foundation(type, ip, stun_turn_ip, transport) do
    {type, ip, stun_turn_ip, transport}
    |> then(&inspect(&1))
    |> then(&:erlang.crc32(&1))
  end

  defp address_to_string(address), do: :inet.ntoa(address)
  defp transport_to_string(:udp), do: "UDP"
end
