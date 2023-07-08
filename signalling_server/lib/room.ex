defmodule SignallingServer.Room do
  use GenServer

  def join() do
    GenServer.call(__MODULE__, {:join, self()})
  end

  def forward(msg) do
    GenServer.call(__MODULE__, {:forward, msg})
  end

  @impl true
  def init(_opts) do
    {:ok, %{p1: nil, p2: nil}}
  end

  @impl true
  def handle_call(:join, from, %{p1: nil} = state) do
    state = put_in(state, :p1, from)
    {:reply, :ok, state}
  end

  @impl true
  def handle_call(:join, from, %{p2: nil} = state) do
    state = put_in(state, :p2, from)
    {:reply, :ok, state}
  end

  @impl true
  def handle_call(:join, _from, state) do
    {:reply, {:error, :room_full}, state}
  end

  @impl true
  def handle_call({:forward, msg}, p1, %{p1: p1} = state) do
    send(state.p2, {:forward, msg})
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:forward, msg}, p2, %{p2: p2} = state) do
    send(state.p1, {:forward, msg})
    {:reply, :ok, state}
  end
end
