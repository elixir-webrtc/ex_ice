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

  @spec recv(ExICE.Priv.Transport.socket()) :: binary() | nil
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
  def transport, do: :udp

  @impl true
  def socket_configs, do: [[]]

  @impl true
  def setup_socket(ip, port, _opts \\ [], _tp_opts \\ []) do
    unless :transport_mock in :ets.all() do
      raise """
      #{__MODULE__} has not been initialized.
      Call #{__MODULE__}.init/0 at system startup,
      in a long running process.
      """
    end

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

        case :ets.lookup(:transport_mock, ref) do
          [{^ref, %{state: :closed}}] ->
            :ets.insert(:transport_mock, {ref, socket})
            {:ok, ref}

          [{^ref, _open}] ->
            raise "Couldn't open socket: #{inspect(socket)}, reason: eaddrinuse."

          [] ->
            :ets.insert(:transport_mock, {ref, socket})
            {:ok, ref}
        end
    end
  end

  @impl true
  def sockname(ref) do
    case :ets.lookup(:transport_mock, ref) do
      [{^ref, %{state: :closed}}] -> {:error, :closed}
      [{^ref, socket}] -> {:ok, {socket.ip, socket.port}}
      [] -> {:error, :closed}
    end
  end

  @impl true
  def send(ref, _dst, packet, _tp_opts \\ []) do
    [{^ref, %{state: :open} = socket}] = :ets.lookup(:transport_mock, ref)

    case Map.get(socket, :send_error) do
      nil ->
        :ets.insert(:transport_mock, {ref, %{socket | buf: socket.buf ++ [packet]}})
        :ok

      reason ->
        {:error, reason}
    end
  end

  @doc """
  Forces subsequent `send/4` calls on `ref` to return `{:error, reason}`.
  """
  @spec fail_send(ExICE.Priv.Transport.socket(), term()) :: :ok
  def fail_send(ref, reason) do
    [{^ref, socket}] = :ets.lookup(:transport_mock, ref)
    :ets.insert(:transport_mock, {ref, Map.put(socket, :send_error, reason)})
    :ok
  end

  @impl true
  def close(ref) do
    case :ets.lookup(:transport_mock, ref) do
      [{^ref, socket}] ->
        # Retain the entry in :closed state so tests can inspect any packets
        # the agent sent in the close path (e.g. TURN Refresh with Lifetime=0).
        :ets.insert(:transport_mock, {ref, %{socket | state: :closed}})

      [] ->
        :ok
    end

    :ok
  end

  defp open_ephemeral(ip) do
    Enum.find_value(49_152..65_535, fn port ->
      socket = %{ip: ip, port: port, state: :open, buf: []}
      ref = :erlang.phash2(socket)

      case :ets.lookup(:transport_mock, ref) do
        [{^ref, %{state: :closed}}] ->
          :ets.insert(:transport_mock, {ref, socket})
          ref

        [{^ref, _open}] ->
          nil

        [] ->
          :ets.insert(:transport_mock, {ref, socket})
          ref
      end
    end)
  end
end
