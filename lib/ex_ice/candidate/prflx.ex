defmodule ExICE.Candidate.Prflx do
  @moduledoc false
  @behaviour ExICE.Candidate

  alias ExICE.CandidateBase

  @type t() :: %__MODULE__{base: ExICE.CandidateBase.t()}

  @enforce_keys [:base]
  defstruct @enforce_keys

  @impl true
  def new(config) do
    config = Keyword.put(config, :type, :prflx)
    %__MODULE__{base: CandidateBase.new(config)}
  end

  @impl true
  defdelegate marshal(cand), to: CandidateBase
  @impl true
  defdelegate family(cand), to: CandidateBase
  @impl true
  defdelegate receive_data(cand, src_ip, src_port, data), to: CandidateBase
end
