defmodule ExICE.CandidatePair do
  @moduledoc """
  Module representing ICE candidate pair.
  """
  require Logger

  alias ExICE.ICEAgent
  alias ExICE.Candidate

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
  @spec new(Candidate.t(), Candidate.t(), ICEAgent.role(), state(), valid?: boolean()) :: t()
  def new(local_cand, remote_cand, agent_role, state, opts \\ []) do
    priority = priority(agent_role, local_cand, remote_cand)

    <<id::12*8>> = :crypto.strong_rand_bytes(12)

    %__MODULE__{
      id: id,
      local_cand: local_cand,
      remote_cand: remote_cand,
      priority: priority,
      state: state,
      valid?: opts[:valid?] || false
    }
  end

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

  @spec recompute_priority(t(), ICEAgent.role()) :: t()
  def recompute_priority(pair, role) do
    %__MODULE__{pair | priority: priority(role, pair.local_cand, pair.remote_cand)}
  end

  defp priority(:controlling, local_cand, remote_cand) do
    do_priority(local_cand.priority, remote_cand.priority)
  end

  defp priority(:controlled, local_cand, remote_cand) do
    do_priority(remote_cand.priority, local_cand.priority)
  end

  defp do_priority(g, d) do
    # refer to RFC 8445 sec. 6.1.2.3
    2 ** 32 * min(g, d) + 2 * max(g, d) + if g > d, do: 1, else: 0
  end
end
