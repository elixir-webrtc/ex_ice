defmodule ExICE.Checklist do
  @moduledoc false

  alias ExICE.ICEAgent
  alias ExICE.CandidatePair
  alias ExICE.Candidate

  @type t() :: map()

  @spec get_next_pair(t()) :: CandidatePair.t()
  def get_next_pair(checklist) do
    # FIXME correctly handle frozen pairs, according to sec 6.1.4.2
    checklist
    |> Enum.filter(fn {_id, pair} -> pair.state in [:frozen, :waiting] end)
    |> Enum.max_by(fn {_id, pair} -> pair.priority end, fn -> {nil, nil} end)
    |> elem(1)
  end

  @spec get_pair_for_nomination(t()) :: CandidatePair.t()
  def get_pair_for_nomination(checklist) do
    checklist
    |> Enum.filter(fn {_id, pair} -> pair.valid? end)
    |> Enum.max_by(fn {_id, pair} -> pair.priority end, fn -> {nil, nil} end)
    |> elem(1)
  end

  @spec get_valid_pair(t()) :: CandidatePair.t()
  def get_valid_pair(checklist) do
    checklist
    |> Enum.find({nil, nil}, fn {_id, pair} -> pair.valid? end)
    |> elem(1)
  end

  @spec find_pair(t(), CandidatePair.t()) :: CandidatePair.t()
  def find_pair(checklist, pair) do
    find_pair(checklist, pair.local_cand, pair.remote_cand)
  end

  @spec find_pair(t(), Candidate.t(), Candidate.t()) :: CandidatePair.t()
  def find_pair(checklist, local_cand, remote_cand) do
    # TODO which pairs are actually the same?
    checklist
    |> Enum.find({nil, nil}, fn {_id, p} ->
      p.local_cand.base_address == local_cand.base_address and
        p.local_cand.base_port == local_cand.base_port and
        p.local_cand.address == local_cand.address and
        p.local_cand.port == local_cand.port and
        p.remote_cand.address == remote_cand.address and
        p.remote_cand.port == remote_cand.port
    end)
    |> elem(1)
  end

  @spec waiting?(t()) :: boolean()
  def waiting?(checklist) do
    Enum.any?(checklist, fn {_id, pair} -> pair.state in [:frozen, :waiting] end)
  end

  @spec in_progress?(t()) :: boolean()
  def in_progress?(checklist) do
    Enum.any?(checklist, fn {_id, pair} -> pair.state == :in_progress end)
  end

  @spec finished?(t()) :: boolean()
  def finished?(checklist) do
    not (waiting?(checklist) or in_progress?(checklist))
  end

  @spec get_foundations(t()) :: [{integer(), integer()}]
  def get_foundations(checklist) do
    for {_id, pair} <- checklist do
      {pair.local_cand.foundation, pair.remote_cand.foundation}
    end
  end

  @spec prune(t()) :: t()
  def prune(checklist) do
    # This is done according to RFC 8838 sec. 10 
    {waiting, in_flight_or_done} =
      Enum.split_with(checklist, fn {_id, p} -> p.state in [:waiting, :frozen] end)

    waiting =
      waiting
      |> Enum.sort_by(fn {_id, p} -> p.priority end, :desc)
      |> Enum.uniq_by(fn {_id, p} ->
        {p.local_cand.base_address, p.local_cand.base_port, p.remote_cand}
      end)

    Map.new(waiting ++ in_flight_or_done)
  end

  @spec timeout_pairs(t(), [integer()]) :: t()
  def timeout_pairs(checklist, ids) do
    for {_id, pair} <- checklist, into: %{} do
      if pair.id in ids do
        {pair.id, %CandidatePair{pair | valid?: false, state: :failed}}
      else
        {pair.id, pair}
      end
    end
  end

  @spec recompute_pair_prios(t(), ICEAgent.role()) :: t()
  def recompute_pair_prios(checklist, role) do
    Map.new(checklist, fn {pair_id, pair} ->
      {pair_id, CandidatePair.recompute_priority(pair, role)}
    end)
  end
end
