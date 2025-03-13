defmodule ExICE.Candidate do
  @moduledoc """
  ICE candidate representation.
  """

  @type type() :: :host | :srflx | :prflx | :relay

  @type t() :: %__MODULE__{
          id: integer(),
          type: type(),
          address: :inet.ip_address() | String.t(),
          base_address: :inet.ip_address() | nil,
          base_port: :inet.port_number() | nil,
          foundation: integer(),
          port: :inet.port_number(),
          priority: integer(),
          transport: :udp | :tcp
        }

  @enforce_keys [
    :id,
    :type,
    :address,
    :port,
    :foundation,
    :priority,
    :transport
  ]
  defstruct @enforce_keys ++ [:base_address, :base_port]

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

    # This is based on RFC 8839 sec. 5.1.
    # Reflexive candidates MUST contain rel-addr and rel-port.
    # However, for security reasons, we always use "0.0.0.0"
    # (or "::" for ipv6) as rel-addr and "9" as rel-port.
    related_addr =
      cond do
        type == :host -> ""
        ExICE.Priv.Utils.family(address) == :ipv4 -> "raddr 0.0.0.0 rport 9"
        ExICE.Priv.Utils.family(address) == :ipv6 -> "raddr :: rport 9"
      end

    transport = transport_to_string(transport)
    address = address_to_string(address)

    "#{foundation} #{component_id} #{transport} #{priority} #{address} #{port} typ #{type} #{related_addr}"
    |> String.trim()
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
       new(
         type,
         address: address,
         port: port,
         priority: priority,
         foundation: foundation,
         transport: transport
       )}
    else
      err when is_list(err) -> {:error, :invalid_candidate}
      err -> err
    end
  end

  @spec family(t()) :: :ipv4 | :ipv6
  def family(%__MODULE__{address: {_, _, _, _}}), do: :ipv4
  def family(%__MODULE__{address: {_, _, _, _, _, _, _, _}}), do: :ipv6

  @doc false
  @spec new(type(), Keyword.t()) :: t()
  def new(type, config) when type in [:host, :srflx, :prflx, :relay] do
    transport = Keyword.get(config, :transport, :udp)

    priority =
      if config[:priority] do
        config[:priority]
      else
        base_address = Keyword.fetch!(config, :base_address)
        ExICE.Priv.Candidate.priority(base_address, type)
      end

    address = Keyword.fetch!(config, :address)

    %__MODULE__{
      id: ExICE.Priv.Utils.id(),
      address: address,
      base_address: config[:base_address],
      base_port: config[:base_port],
      foundation: ExICE.Priv.Candidate.foundation(type, address, nil, transport),
      port: Keyword.fetch!(config, :port),
      priority: priority,
      transport: transport,
      type: type
    }
  end

  defp address_to_string(address) when is_binary(address), do: address
  defp address_to_string(address), do: :inet.ntoa(address)

  defp transport_to_string(:udp), do: "UDP"

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
end
