defmodule ExICE.Support.Transport.Mock do
  @moduledoc false

  # Simple ExICE.Transport mock that saves last sent packet
  # in `:transport_mock` ets table under `socket` key.

  @behaviour ExICE.Priv.Transport

  @doc """
  Initializes mock transport.

  This function creates an ets table under the hood so
  it has to be re-called after the calling process terminates
  or it has to be called in a long running process.
  """
  @spec init() :: :ok
  def init() do
    # Use ets to store last sent packet.
    # Create ets only if it doesn't exist.
    try do
      # public - any process can read or write to the table
      :ets.new(:transport_mock, [:named_table, :public])
      :ok
    rescue
      _ -> :ok
    end
  end

  @spec recv(ExICE.Transport.socket()) :: binary() | nil
  def recv(socket) do
    [{_socket, packet}] = :ets.lookup(:transport_mock, socket)
    packet
  end

  @impl true
  def open(port, opts) do
    unless :transport_mock in :ets.all() do
      raise """
      #{__MODULE__} has not been initialized.
      Call #{__MODULE__}.init/0 at system startup,
      in a long running process.
      """
    end

    ip = Keyword.get(opts, :ip, {0, 0, 0, 0})

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
