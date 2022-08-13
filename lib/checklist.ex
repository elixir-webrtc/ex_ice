defmodule ExICE.Checklist do
  @moduledoc """
  ICE agent checklist.
  """

  @type t() :: %__MODULE__{
          state: :running | :completed | :failed,
          pairs: [__MODULE__.CandidatePair.t()]
        }

  defstruct state: :running,
            pairs: []
end
