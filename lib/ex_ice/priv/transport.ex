defmodule ExICE.Priv.Transport do
  @moduledoc false

  @type socket() :: term()

  @callback open(:inet.port_number(), [:gen_udp.open_option()]) ::
              {:ok, socket()} | {:error, term()}

  @callback sockname(socket()) ::
              {:ok, {:inet.ip_address(), :inet.port_number()}} | {:error, term()}

  @callback send(socket(), {:inet.ip_address(), :inet.port_number()}, binary()) ::
              :ok | {:error, term()}

  @callback close(socket()) :: :ok
end
