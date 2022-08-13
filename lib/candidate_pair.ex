defmodule ExICE.CandidatePair do
  @moduledoc """
  Module representing ICE candidate pair.
  """

  alias ExICE.Worker

  @type t() :: %__MODULE__{
          local_cand: Candidate.t(),
          nominated?: boolean(),
          priority: non_neg_integer(),
          remote_cand: Candidate.t(),
          state: :waiting | :in_progress | :succeeded | :failed | :frozen
        }

  @enforce_keys [:local_cand, :remote_cand, :priority]
  defstruct @enforce_keys ++
              [
                nominated?: false,
                state: :frozen
              ]

  @spec new(Worker.role(), Candidate.t(), Candidate.t()) :: t()
  def new(agent_role, local_cand, remote_cand) do
    priority = priority(agent_role, local_cand, remote_cand)

    %__MODULE__{
      local_cand: local_cand,
      remote_cand: remote_cand,
      priority: priority
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
