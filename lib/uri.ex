defmodule ExIce.URI do
  @moduledoc """
  Module representing STUN URI.

  Implementation of RFC 7064.

  We could try to use URI module from Elixir
  but RFC 7064 states:

    While these two ABNF productions are defined in [RFC3986]
    as components of the generic hierarchical URI, this does
    not imply that the "stun" and "stuns" URI schemes are
    hierarchical URIs.  Developers MUST NOT use a generic
    hierarchical URI parser to parse a "stun" or "stuns" URI.

  """

  @type scheme :: :stun | :stuns

  @type t() :: %__MODULE__{
          scheme: scheme(),
          host: String.t(),
          port: :inet.port_number()
        }

  @enforce_keys [:host]
  defstruct @enforce_keys ++ [scheme: :stun, port: 3478]

  @doc """
  Parses URI string into `t:t/0`.
  """
  @spec parse(String.t()) :: {:ok, t()} | :error
  def parse("stun" <> ":" <> host_and_port) do
    do_parse(:stun, host_and_port)
  end

  def parse("stuns" <> ":" <> host_and_port) do
    do_parse(:stuns, host_and_port)
  end

  def parse(_other), do: :error

  defp do_parse(scheme, host_and_port) do
    case String.split(host_and_port, ":") do
      [host, port] when host != "" ->
        case Integer.parse(port) do
          {port, ""} -> {:ok, %__MODULE__{scheme: scheme, host: host, port: port}}
          :error -> :error
        end

      [host] when host != "" ->
        {:ok, %__MODULE__{scheme: scheme, host: host}}

      _other ->
        :error
    end
  end
end
