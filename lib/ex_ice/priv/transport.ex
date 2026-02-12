defmodule ExICE.Priv.Transport do
  @moduledoc false

  @type socket :: term()

  @type open_option ::
          :inet.inet_backend()
          | :inet.address_family()
          | {:ip, :inet.socket_address()}
          | :inet.socket_setopt()

  @type transport_options :: Keyword.t()

  @callback transport() :: atom()

  @callback socket_configs() :: [transport_options()]

  @callback setup_socket(
              :inet.ip_address(),
              :inet.port_number(),
              [open_option()],
              transport_options()
            ) ::
              {:ok, socket()} | {:error, term()}

  @callback sockname(socket()) ::
              {:ok, {:inet.ip_address(), :inet.port_number()}} | {:error, term()}

  @callback send(
              socket(),
              {:inet.ip_address(), :inet.port_number()},
              binary(),
              transport_options()
            ) ::
              :ok | {:error, term()}

  @callback close(socket()) :: :ok
end
