defmodule ExICE.CandidatePair do
  @moduledoc """
  ICE candidate pair representation.
  """

  alias ExICE.Candidate

  @type state() :: :waiting | :in_progress | :succeeded | :failed | :frozen

  @type t() :: %__MODULE__{
          id: integer(),
          local_cand: Candidate.t(),
          nominated?: boolean(),
          priority: non_neg_integer(),
          remote_cand: Candidate.t(),
          state: state(),
          valid?: boolean()
        }

  @enforce_keys [:id, :local_cand, :remote_cand, :priority]
  defstruct @enforce_keys ++
              [
                nominated?: false,
                state: :frozen,
                valid?: false
              ]
end
