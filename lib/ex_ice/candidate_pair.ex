defmodule ExICE.CandidatePair do
  @moduledoc """
  ICE candidate pair representation.
  """

  @type state() :: :waiting | :in_progress | :succeeded | :failed | :frozen

  @type t() :: %__MODULE__{
          id: integer(),
          local_cand_id: integer(),
          nominated?: boolean(),
          priority: non_neg_integer(),
          remote_cand_id: integer(),
          state: state(),
          valid?: boolean(),
          last_seen: integer(),
          # stats
          requests_received: non_neg_integer(),
          requests_sent: non_neg_integer(),
          responses_received: non_neg_integer(),
          non_symmetric_responses_received: non_neg_integer(),
          responses_sent: non_neg_integer()
        }

  @enforce_keys [:id, :local_cand_id, :remote_cand_id, :priority]
  defstruct @enforce_keys ++
              [
                nominated?: false,
                state: :frozen,
                valid?: false,
                last_seen: nil,
                requests_received: 0,
                requests_sent: 0,
                responses_received: 0,
                non_symmetric_responses_received: 0,
                responses_sent: 0
              ]
end
