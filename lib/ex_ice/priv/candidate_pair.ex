defmodule ExICE.Priv.CandidatePair do
  @moduledoc false
  require Logger

  alias ExICE.Priv.{Candidate, Utils}

  # Tr timeout (keepalives) in ms
  @tr_timeout 15 * 1000

  @type state() :: :waiting | :in_progress | :succeeded | :failed | :frozen

  @type t() :: %__MODULE__{
          id: integer(),
          local_cand: Candidate.t(),
          nominate?: boolean(),
          nominated?: boolean(),
          priority: non_neg_integer(),
          remote_cand: Candidate.t(),
          state: state(),
          valid?: boolean,
          succeeded_pair_id: integer() | nil,
          discovered_pair_id: integer() | nil,
          keepalive_timer: reference() | nil
        }

  @enforce_keys [:id, :local_cand, :remote_cand, :priority]
  defstruct @enforce_keys ++
              [
                nominate?: false,
                nominated?: false,
                state: :frozen,
                valid?: false,
                succeeded_pair_id: nil,
                discovered_pair_id: nil,
                keepalive_timer: nil
              ]

  @doc false
  @spec new(Candidate.t(), Candidate.t(), ExICE.ICEAgent.role(), state(), valid?: boolean()) ::
          t()
  def new(local_cand, remote_cand, agent_role, state, opts \\ []) do
    priority = priority(agent_role, local_cand, remote_cand)

    %__MODULE__{
      id: Utils.id(),
      local_cand: local_cand,
      remote_cand: remote_cand,
      priority: priority,
      state: state,
      valid?: opts[:valid?] || false
    }
  end

  @doc false
  @spec schedule_keepalive(t(), Process.dest()) :: t()
  def schedule_keepalive(pair, dest \\ self())

  def schedule_keepalive(%{keepalive_timer: timer} = pair, dest) when is_reference(timer) do
    Process.cancel_timer(timer)
    schedule_keepalive(%{pair | keepalive_timer: nil}, dest)
  end

  def schedule_keepalive(pair, dest) do
    ref = Process.send_after(dest, {:keepalive, pair.id}, @tr_timeout)
    %{pair | keepalive_timer: ref}
  end

  @doc false
  @spec recompute_priority(t(), ExICE.ICEAgent.role()) :: t()
  def recompute_priority(pair, role) do
    %__MODULE__{pair | priority: priority(role, pair.local_cand, pair.remote_cand)}
  end

  @doc false
  @spec priority(ExICE.ICEAgent.role(), Candidate.t(), ExICE.Candidate.t()) :: non_neg_integer()
  def priority(:controlling, local_cand, remote_cand) do
    do_priority(local_cand.base.priority, remote_cand.priority)
  end

  def priority(:controlled, local_cand, remote_cand) do
    do_priority(remote_cand.priority, local_cand.base.priority)
  end

  defp do_priority(g, d) do
    # refer to RFC 8445 sec. 6.1.2.3
    2 ** 32 * min(g, d) + 2 * max(g, d) + if g > d, do: 1, else: 0
  end

  @doc false
  @spec to_candidate_pair(t()) :: ExICE.CandidatePair.t()
  def to_candidate_pair(pair) do
    %cand_mod{} = cand = pair.local_cand
    local_cand = cand_mod.to_candidate(cand)

    %ExICE.CandidatePair{
      id: pair.id,
      local_cand: local_cand,
      nominated?: pair.nominated?,
      priority: pair.priority,
      remote_cand: pair.remote_cand,
      state: pair.state,
      valid?: pair.valid?
    }
  end
end
