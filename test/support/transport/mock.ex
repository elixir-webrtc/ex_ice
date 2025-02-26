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
  def recv(ref) do
    case :ets.lookup(:transport_mock, ref) do
      [{^ref, %{buf: []} = _socket}] ->
        nil

      [{^ref, %{buf: [head | tail]} = socket}] ->
        :ets.insert(:transport_mock, {ref, %{socket | buf: tail}})
        head
    end
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
        ref = open_ephemeral(ip)

        if ref == nil do
          raise "Couldn't open socket. No free ports"
        end

        {:ok, ref}

      port ->
        socket = %{port: port, ip: ip, state: :open, buf: []}
        ref = :erlang.phash2(socket)

        unless :ets.insert_new(:transport_mock, {ref, socket}) do
          raise "Couldn't open socket: #{inspect(socket)}, reason: eaddrinuse."
        end

        {:ok, ref}
    end
  end

  @impl true
  def sockname(ref) do
    [{^ref, socket}] = :ets.lookup(:transport_mock, ref)
    {:ok, {socket.ip, socket.port}}
  end

  @impl true
  def send(ref, _dst, packet) do
    [{^ref, %{state: :open} = socket}] = :ets.lookup(:transport_mock, ref)
    :ets.insert(:transport_mock, {ref, %{socket | buf: socket.buf ++ [packet]}})
    :ok
  end

  @impl true
  def close(ref) do
    :ets.delete(:transport_mock, ref)
    :ok
  end

  defp open_ephemeral(ip) do
    Enum.find_value(49_152..65_535, fn port ->
      socket = %{ip: ip, port: port, state: :open, buf: []}
      ref = :erlang.phash2(socket)

      if :ets.insert_new(:transport_mock, {ref, socket}) do
        ref
      else
        nil
      end
    end)
  end
end
