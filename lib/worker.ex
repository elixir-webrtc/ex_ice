defmodule ExICE.Worker do
  @moduledoc """
  ICE worker.

  In most implementations this module is called Agent.
  However, because of Elixir having builtin Agent module
  which behavior is far more different than behavior of
  this module, this module was called Worker.
  """
  use GenServer

  require Logger

  alias ExICE.Worker.State

  @type role() :: :controlling | :controlled

  @type opts() :: [
          stun_servers :: [String.t()]
        ]

  @spec start_link(opts()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts)
  end

  @spec gather_candidates(pid()) :: :ok
  def gather_candidates(ice_agent) do
    GenServer.cast(ice_agent, :gather_candidates)
  end

  @spec add_remote_candidate(pid(), String.t()) :: :ok
  def add_remote_candidate(ice_agent, candidate) do
    GenServer.cast(ice_agent, {:add_remote_candidate, candidate})
  end

  ### Server

  @impl true
  def init(opts) do
    {:ok, State.new(opts)}
  end

  @impl true
  def handle_cast(:gather_candidates, state) do
    {:noreply, State.gather_candidates(state)}
  end

  @impl true
  def handle_cast({:add_remote_candidate, candidate}, state) do
    {:noreply, State.add_remote_candidate(state, candidate)}
  end
end
