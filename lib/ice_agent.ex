defmodule ExIce.IceAgent do
  @moduledoc """
  ICE agent.
  """
  use GenServer

  alias ExIce.{Candidate, Checklist}

  @type role() :: :controlling | :controlled

  @type t() :: %__MODULE__{
          candidates: [Candidate.t()],
          checklist: Checklist.t(),
          controlling_process: pid()
        }

  defstruct [
    :checklist,
    :controlling_process,
    candidates: []
  ]

  @spec start_link(any()) :: GenServer.on_start()
  def start_link(init_arg \\ []) do
    GenServer.start_link(__MODULE__, init_arg)
  end

  @spec gather_candidates(pid()) :: :ok
  def gather_candidates(agent) do
    GenServer.cast(agent, :gather_candidates)
  end

  ### Server

  @impl true
  def init(_init_arg) do
    {:ok, %__MODULE__{}}
  end

  @impl true
  def handle_cast(:gather_candidates, state) do
    {:noreply, state}
  end
end
