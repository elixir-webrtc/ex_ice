defmodule ExICE.Priv.App do
  @moduledoc false
  use Application

  require Logger

  @impl true
  def start(_type, _args) do
    kernel_ver = kernel_version()

    children =
      if kernel_ver >= {9, 1} do
        [{ExICE.Priv.MDNS.Resolver, :gen_udp}]
      else
        Logger.warning("""
        Not starting MDNS resolver as it requires kernel version >= 9.1.
        Detected kernel version: #{inspect(kernel_ver)}
        """)

        []
      end

    Supervisor.start_link(children, strategy: :one_for_one)
  end

  defp kernel_version() do
    ver =
      Application.spec(:kernel, :vsn)
      |> to_string()
      |> String.split(".")

    major = Enum.at(ver, 0) |> String.to_integer()
    minor = Enum.at(ver, 1) |> String.to_integer()

    {major, minor}
  end
end
