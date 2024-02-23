defmodule ExICE.Support.Transport.Mock do
  @moduledoc false

  # Simple ExICE.Transport mock that saves last sent packet
  # in `:transport_mock` ets table under `socket` key.

  @behaviour ExICE.Transport

  @impl true
  def open(port, opts) do
    # Use ets to store last sent packet.
    # Create ets only if it doesn't exist.
    try do
      :ets.new(:transport_mock, [:named_table])
    rescue
      _ -> :ok
    end

    ip = Keyword.fetch!(opts, :ip)

    case port do
      0 ->
        socket = open_ephemeral(ip)

        if socket == nil do
          raise "Couldn't open socket. No free ports"
        end

        {:ok, socket}

      port ->
        socket = %{port: port, ip: ip}

        unless :ets.insert_new(:transport_mock, {socket, nil}) do
          raise "Couldn't open socket: #{inspect(socket)}, reason: eaddrinuse."
        end

        {:ok, socket}
    end
  end

  @impl true
  def sockname(socket) do
    {:ok, {socket.ip, socket.port}}
  end

  @impl true
  def send(socket, _dst, packet) do
    :ets.insert(:transport_mock, {socket, packet})
    :ok
  end

  @impl true
  def close(socket) do
    :ets.delete(:transport_mock, socket)
    :ok
  end

  defp open_ephemeral(ip) do
    Enum.find_value(49_152..65_535, fn port ->
      socket = %{ip: ip, port: port}

      if :ets.insert_new(:transport_mock, {socket, nil}) do
        socket
      else
        false
      end
    end)
  end
end
