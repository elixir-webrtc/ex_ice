defmodule ExICE.Priv.Candidate.Prflx do
  @moduledoc false
  @behaviour ExICE.Priv.Candidate

  alias ExICE.Priv.CandidateBase

  @type t() :: %__MODULE__{base: CandidateBase.t()}

  @enforce_keys [:base]
  defstruct @enforce_keys

  @impl true
  def new(config) do
    %__MODULE__{base: CandidateBase.new(:prflx, config)}
  end

  @impl true
  def marshal(cand), do: CandidateBase.marshal(cand.base)

  @impl true
  def family(cand), do: CandidateBase.family(cand.base)

  @impl true
  def tcp_type(cand), do: CandidateBase.tcp_type(cand.base)

  @impl true
  def to_candidate(cand), do: CandidateBase.to_candidate(cand.base)

  @impl true
  def send_data(cand, dst_ip, dst_port, data) do
    case cand.base.transport_module.send(cand.base.socket, {dst_ip, dst_port}, data) do
      :ok -> {:ok, cand}
      {:error, reason} -> {:error, reason, cand}
    end
  end
end
