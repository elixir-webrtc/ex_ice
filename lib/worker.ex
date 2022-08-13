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

  alias ExICE.{Candidate, Checklist, Gatherer}

  @type role() :: :controlling | :controlled

  @type opts() :: [
          stun_servers :: [String.t()]
        ]

  @type t() :: %__MODULE__{
          checklist: Checklist.t(),
          controlling_process: pid(),
          gather_sup: Supervisor.supervisor(),
          local_candidates: [Candidate.t()],
          remote_candidates: [Candidate.t()],
          stun_servers: [ExICE.URI.t()],
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
    stun_servers =
      (opts[:stun_servers] || [])
      |> Enum.map(fn stun_server ->
        case ExICE.URI.parse(stun_server) do
          {:ok, stun_server} ->
            stun_server

          :error ->
            Logger.warn("""
            Couldn't parse STUN server URI: #{inspect(stun_server)}. \
            Ignoring.\
            """)

            nil
        end
      end)
      |> Enum.reject(&(&1 == nil))

    {:ok, gather_sup} = Task.Supervisor.start_link()
    {:ok, %__MODULE__{gather_sup: gather_sup, stun_servers: stun_servers}}
  end

  @impl true
  def handle_cast(:gather_candidates, state) do
    {:ok, host_candidates} = Gatherer.gather_host_candidates()
    state = %{state | local_candidates: host_candidates}

    Enum.each(state.stun_servers, fn stun_server ->
      Enum.each(host_candidates, fn host_candidate ->
        Task.Supervisor.start_child(state.gather_sup, ExICE.Gatherer, :gather_srflx_candidate, [
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
