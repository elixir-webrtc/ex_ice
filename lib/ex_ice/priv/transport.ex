defmodule ExICE.Priv.Transport do
  @moduledoc false

  @type socket :: term()
  @type open_option ::
          :inet.inet_backend()
          | :inet.address_family()
          | {:ip, :inet.socket_address()}
          | :inet.socket_setopt()

  @callback transport() :: atom()

  @callback socket_configs() :: [map()]

  @callback setup_socket(:inet.ip_address(), :inet.port_number(), [open_option()], map()) ::
              {:ok, socket()} | {:error, term()}

  @callback sockname(socket()) ::
              {:ok, {:inet.ip_address(), :inet.port_number()}} | {:error, term()}

  @callback send(socket(), {:inet.ip_address(), :inet.port_number()}, binary(), Keyword.t()) ::
              :ok | {:error, term()}

  @callback close(socket()) :: :ok
end
