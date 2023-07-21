defmodule ExICE.Candidate do
  @moduledoc """
  ICE candidate representation.
  """

  @type type() :: :host | :srflx | :prflx

  @type t() :: %__MODULE__{
          address: :inet.ip_address(),
          base_address: :inet.ip_address() | nil,
          base_port: :inet.port_number() | nil,
          foundation: integer(),
          port: :inet.port_number(),
          priority: integer(),
          transport: :udp,
          socket: :inet.socket() | nil,
          type: :host | :srflx | :prflx
        }

  @derive {Inspect, except: [:socket]}
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
  def new(type, address, port, base_address, base_port, socket)
      when type in [:host, :srflx, :prflx, :relay] do
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

  @spec unmarshal(String.t()) :: {:ok, t()} | {:error, term()}
  def unmarshal(string) do
    with [f_str, c_str, tr_str, pr_str, a_str, po_str, "typ", ty_str] <-
           String.split(string, " ", parts: 8),
         {foundation, ""} <- Integer.parse(f_str),
         {_component_id, ""} <- Integer.parse(c_str),
         {:ok, transport} <- parse_transport(String.downcase(tr_str)),
         {priority, ""} <- Integer.parse(pr_str),
         {:ok, address} <- :inet.parse_address(String.to_charlist(a_str)),
         {port, ""} <- Integer.parse(po_str),
         {:ok, type} <- parse_type(ty_str) do
      {:ok,
       %__MODULE__{
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

  defp parse_transport("udp"), do: {:ok, :udp}
  defp parse_transport(_other), do: {:error, :invalid_transport}

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
