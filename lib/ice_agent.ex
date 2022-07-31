defmodule ExIce.IceAgent do
  @moduledoc """
  ICE agent.
  """
  use GenServer

  alias ExIce.{Candidate, Checklist, Gatherer}

  @type role() :: :controlling | :controlled

  @type t() :: %__MODULE__{
          checklist: Checklist.t(),
          controlling_process: pid(),
          gather_sup: Supervisor.supervisor(),
          local_candidates: [Candidate.t()],
          remote_candidates: [Candidate.t()],
          stun_servers: [],
          turn_servers: []
        }

  defstruct [
    :checklist,
    :controlling_process,
    :gather_sup,
    local_candidates: [],
    remote_candidates: [],
    stun_servers: [],
    turn_servers: []
  ]

  @spec start_link(any()) :: GenServer.on_start()
  def start_link(init_arg \\ []) do
    GenServer.start_link(__MODULE__, init_arg)
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
  def init(_init_arg) do
    gather_sup = Task.Supervisor.start_link()
    {:ok, %__MODULE__{gather_sup: gather_sup}}
  end

  @impl true
  def handle_cast(:gather_candidates, state) do
    {:ok, host_candidates} = Gatherer.gather_host_candidates()
    state = %{state | local_candidates: host_candidates}

    Enum.each(state.stun_servers, fn stun_server ->
      Enum.each(host_candidates, fn host_candidate ->
        Task.Supervisor.start_child(state.gather_sup, ExIce.Gatherer, :gather_srflx_candidate, [
          self(),
          host_candidate,
          stun_server
        ])
      end)
    end)

    {:noreply, state}
  end

  @impl true
  def handle_cast({:add_remote_candidate, candidate}, state) do
    state = %__MODULE__{state | remote_candidates: state.remote_candidates ++ [candidate]}
    {:noreply, state}
  end
end
