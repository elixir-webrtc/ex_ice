defmodule ExICE.Worker.State do
  @moduledoc false

  require Logger

  alias ExICE.{Candidate, Checklist, Gatherer, Worker}

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

  @spec new(Worker.opts()) :: t()
  def new(opts) do
    stun_servers =
      opts
      |> Keyword.get(:stun_servers, [])
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
    %__MODULE__{gather_sup: gather_sup, stun_servers: stun_servers}
  end

  @spec gather_candidates(t()) :: t()
  def gather_candidates(state) do
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

    state
  end

  @spec add_remote_candidate(t(), String.t()) :: t()
  def add_remote_candidate(state, candidate) do
    %__MODULE__{state | remote_candidates: state.remote_candidates ++ [candidate]}
  end
end
