defmodule ExICE.Candidate do
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

  @callback receive_data(t(), :inet.ip_address(), :inet.port_number(), binary()) ::
              {:ok, t()} | {:ok, binary(), t()} | {:error, term(), t()}

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
         {:ok, type} <- parse_type(ty_str),
         {:ok, module} <- to_module(type) do
      {:ok,
       module.new(
         adress: address,
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

  defp to_module(:host), do: {:ok, __MODULE__.Host}
  defp to_module(:srflx), do: {:ok, __MODULE__.Srflx}
  defp to_module(:prflx), do: {:ok, __MODULE__.Prflx}
  defp to_module(:relay), do: {:ok, __MODULE__.Relay}
  defp to_module(_), do: {:error, :unknown_type}
end
