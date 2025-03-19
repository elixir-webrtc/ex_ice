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
          packets_sent: non_neg_integer(),
          packets_received: non_neg_integer(),
          bytes_sent: non_neg_integer(),
          bytes_received: non_neg_integer(),
          requests_received: non_neg_integer(),
          requests_sent: non_neg_integer(),
          responses_received: non_neg_integer(),
          non_symmetric_responses_received: non_neg_integer(),
          responses_sent: non_neg_integer(),
          packets_discarded_on_send: non_neg_integer(),
          bytes_discarded_on_send: non_neg_integer()
        }

  @enforce_keys [:id, :local_cand_id, :remote_cand_id, :priority]
  defstruct @enforce_keys ++
              [
                nominated?: false,
                state: :frozen,
                valid?: false,
                last_seen: nil,
                packets_sent: 0,
                packets_received: 0,
                bytes_sent: 0,
                bytes_received: 0,
                requests_received: 0,
                requests_sent: 0,
                responses_received: 0,
                non_symmetric_responses_received: 0,
                responses_sent: 0,
                packets_discarded_on_send: 0,
                bytes_discarded_on_send: 0
              ]
end
