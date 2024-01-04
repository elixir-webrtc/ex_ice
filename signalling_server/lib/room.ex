defmodule SignallingServer.Room do
  use GenServer

  require Logger

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def join() do
    GenServer.call(__MODULE__, :join)
  end

  def forward(msg) do
    GenServer.call(__MODULE__, {:forward, msg})
  end

  @impl true
  def init(_opts) do
    Logger.info("Creating the room")
    {:ok, %{p1: nil, p1_ref: nil, p2: nil, p2_ref: nil}}
  end

  @impl true
  def handle_call(:join, {from, _}, %{p1: nil} = state) do
    ref = Process.monitor(from)
    state = %{state | p1: from, p1_ref: ref}
    {:reply, :ok, state}
  end

  @impl true
  def handle_call(:join, {from, _}, %{p2: nil} = state) do
    ref = Process.monitor(from)
    state = %{state | p2: from, p2_ref: ref}

    if state.p1 do
      send(state.p2, {:forward, Jason.encode!(%{type: "peer_joined", role: "controlled"})})
      send(state.p1, {:forward, Jason.encode!(%{type: "peer_joined", role: "controlling"})})
    end

    {:reply, :ok, state}
  end

  @impl true
  def handle_call(:join, _from, state) do
    {:reply, {:error, :room_full}, state}
  end

  @impl true
  def handle_call({:forward, msg}, {p1, _}, %{p1: p1} = state) do
    if state.p2 do
      send(state.p2, {:forward, msg})
    else
      Logger.warning("Not forwarding msg as there is no p2")
    end

    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:forward, msg}, {p2, _}, %{p2: p2} = state) do
    if state.p1 do
      send(state.p1, {:forward, msg})
    else
      Logger.warning("Not forwarding msg as there is no p1")
    end

    {:reply, :ok, state}
  end

  @impl true
  def handle_info({:DOWN, ref, _, _, _}, state) do
    Logger.info("Peer left the room")

    state =
      if ref == state.p1_ref do
        if state.p2 do
          send(state.p2, {:forward, Jason.encode!(%{type: "peer_left"})})
        end

        %{state | p1_ref: nil, p1: nil}
      else
        if state.p1 do
          send(state.p1, {:forward, Jason.encode!(%{type: "peer_left"})})
        end

        %{state | p2_ref: nil, p2: nil}
      end

    {:noreply, state}
  end
end
