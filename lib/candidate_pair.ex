defmodule ExICE.CandidatePair do
  @moduledoc """
  Module representing ICE candidate pair.
  """
  require Logger

  alias ExICE.ICEAgent
  alias ExICE.Candidate

  @type state() :: :waiting | :in_progress | :succeeded | :failed | :frozen

  @type t() :: %__MODULE__{
          id: integer(),
          local_cand: Candidate.t(),
          nominate?: boolean(),
          nominated?: boolean(),
          priority: non_neg_integer(),
          remote_cand: Candidate.t(),
          state: state(),
          valid?: boolean
        }

  @enforce_keys [:id, :local_cand, :remote_cand, :priority]
  defstruct @enforce_keys ++
              [
                nominate?: false,
                nominated?: false,
                state: :frozen,
                valid?: false
              ]

  @doc false
  @spec new(Candidate.t(), Candidate.t(), ICEAgent.role(), state()) :: t()
  def new(local_cand, remote_cand, agent_role, state) do
    priority = priority(agent_role, local_cand, remote_cand)

    <<id::12*8>> = :crypto.strong_rand_bytes(12)

    %__MODULE__{
      id: id,
      local_cand: local_cand,
      remote_cand: remote_cand,
      priority: priority,
      state: state
    }
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
