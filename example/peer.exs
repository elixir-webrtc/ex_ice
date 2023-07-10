Mix.install([{:gun, "~> 2.0.1"}, {:ex_ice, path: "../"}, {:jason, "~> 1.4.0"}])

defmodule Peer do
  use GenServer

  alias ExICE.ICEAgent

  require Logger

  def start_link() do
    GenServer.start_link(__MODULE__, [])
  end

  @impl true
  def init(_) do
    {signalling_ip, signalling_port} =
      case System.argv() do
        [ip, port] ->
          {:ok, ip} = :inet.parse_address(String.to_charlist(ip))
          port = String.to_integer(port)
          {ip, port}

        [] ->
          {{127, 0, 0, 1}, 4000}
      end

    {:ok, conn} = :gun.open(signalling_ip, signalling_port)
    {:ok, _protocol} = :gun.await_up(conn)
    :gun.ws_upgrade(conn, "/websocket")

    receive do
      {:gun_upgrade, ^conn, stream, _, _} ->
        Logger.info("Connected to the signalling server")
        {:ok, %{conn: conn, stream: stream, ice: nil}}

      other ->
        Logger.error("Couldn't connect to the signalling server: #{inspect(other)}")
        exit(:error)
    after
      1000 ->
        exit(:timeout)
    end
  end

  @impl true
  def handle_info({:gun_down, _, :ws, :closed, _}, state) do
    Logger.info("Server closed ws connection. Exiting")
    {:stop, :normal, state}
  end

  @impl true
  def handle_info({:gun_ws, _, _, {:text, msg}}, state) do
    state = handle_ws_msg(Jason.decode!(msg), state)
    {:noreply, state}
  end

  @impl true
  def handle_info({:ex_ice, _pid, msg}, state) do
    state = handle_ice_msg(msg, state)
    {:noreply, state}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.warn("Received unknown msg: #{inspect(msg)}")
    {:noreply, state}
  end

  defp handle_ws_msg(%{"type" => "peer_joined", "role" => role}, state) do
    Logger.info("Peer joined. Starting ICE.")
    role = String.to_atom(role)

    {:ok, pid} =
      ICEAgent.start_link(role,
        ip_filter: fn _ -> true end,
        stun_servers: ["stun:stun.l.google.com:19302"]
      )

    :ok = ICEAgent.run(pid)
    %{state | ice: pid}
  end

  defp handle_ws_msg(%{"type" => "credentials", "ufrag" => ufrag, "passwd" => passwd}, state) do
    :ok =
      ICEAgent.set_remote_credentials(state.ice, Base.decode64!(ufrag), Base.decode64!(passwd))

    state
  end

  defp handle_ws_msg(%{"type" => "candidate", "cand" => cand}, state) do
    :ok = ICEAgent.add_remote_candidate(state.ice, cand)
    state
  end

  defp handle_ws_msg(%{"type" => "end_of_candidates"}, state) do
    :ok = ICEAgent.end_of_candidates(state.ice)
    state
  end

  def handle_ice_msg({:local_credentials, ufrag, passwd}, state) do
    msg =
      %{type: "credentials", ufrag: Base.encode64(ufrag), passwd: Base.encode64(passwd)}
      |> Jason.encode!()

    :gun.ws_send(state.conn, state.stream, {:text, msg})
    state
  end

  def handle_ice_msg({:new_candidate, cand}, state) do
    msg = %{type: "candidate", cand: cand} |> Jason.encode!()
    :gun.ws_send(state.conn, state.stream, {:text, msg})
    state
  end

  def handle_ice_msg(:gathering_complete, state) do
    msg = %{type: "end_of_candidates"} |> Jason.encode!()
    :gun.ws_send(state.conn, state.stream, {:text, msg})
    state
  end

  def handle_ice_msg(other, state) do
    Logger.info("ICE: #{inspect(other)}")
    state
  end
end

require Logger

{:ok, pid} = Peer.start_link()
ref = Process.monitor(pid)

receive do
  {:DOWN, ^ref, _, _, _} ->
    Logger.info("Peer process closed. Exiting")

  other ->
    Logger.warn("Unexpected msg. Exiting. Msg: #{inspect(other)}")
end
