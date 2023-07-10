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
    {:ok, %{p1: nil, p2: nil}}
  end

  @impl true
  def handle_call(:join, {from, _}, %{p1: nil} = state) do
    state = put_in(state, [:p1], from)
    {:reply, :ok, state}
  end

  @impl true
  def handle_call(:join, {from, _}, %{p2: nil} = state) do
    state = put_in(state, [:p2], from)

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
    send(state.p2, {:forward, msg})
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:forward, msg}, {p2, _}, %{p2: p2} = state) do
    send(state.p1, {:forward, msg})
    {:reply, :ok, state}
  end
end
