defmodule ExICE.Priv.Checklist do
  @moduledoc false

  alias ExICE.Priv.{Candidate, CandidatePair}

  @type t() :: map()

  @spec get_next_pair(t()) :: CandidatePair.t() | nil
  def get_next_pair(checklist) do
    # FIXME correctly handle frozen pairs, according to sec 6.1.4.2
    checklist
    |> Enum.filter(fn {_id, pair} -> pair.state in [:frozen, :waiting] end)
    |> Enum.max_by(fn {_id, pair} -> pair.priority end, fn -> {nil, nil} end)
    |> elem(1)
  end

  @spec get_pair_for_nomination(t()) :: CandidatePair.t() | nil
  def get_pair_for_nomination(checklist) do
    checklist
    |> Enum.filter(fn {_id, pair} -> pair.valid? end)
    |> Enum.max_by(fn {_id, pair} -> pair.priority end, fn -> {nil, nil} end)
    |> elem(1)
  end

  @spec get_valid_pair(t()) :: CandidatePair.t() | nil
  def get_valid_pair(checklist) do
    checklist
    |> Stream.map(fn {_id, pair} -> pair end)
    |> Stream.filter(fn pair -> pair.valid? end)
    |> Enum.sort_by(fn pair -> pair.priority end, :desc)
    |> Enum.at(0)
  end

  @spec find_pair(t(), CandidatePair.t()) :: CandidatePair.t() | nil
  def find_pair(checklist, pair) do
    find_pair(checklist, pair.local_cand_id, pair.remote_cand_id)
  end

  @spec find_pair(t(), integer(), integer()) :: CandidatePair.t() | nil
  def find_pair(checklist, local_cand_id, remote_cand_id) do
    checklist
    |> Enum.find({nil, nil}, fn {_id, p} ->
      p.local_cand_id == local_cand_id and p.remote_cand_id == remote_cand_id
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

  @spec prune(t()) :: t()
  def prune(checklist) do
    # This is done according to RFC 8838 sec. 10
    {waiting, in_flight_or_done} =
      Enum.split_with(checklist, fn {_id, p} -> p.state in [:waiting, :frozen] end)

    waiting =
      waiting
      |> Enum.sort_by(fn {_id, p} -> p.priority end, :desc)
      # RFC 8445, sec. 6.1.2.4. states that two candidate pairs
      # are redundant if their local candidates have the same base
      # and their remote candidates are identical.
      # But, because we replace reflexive candidates with their bases,
      # checking againts local_cand_id should work fine.
      |> Enum.uniq_by(fn {_id, p} -> {p.local_cand_id, p.remote_cand_id} end)

    Map.new(waiting ++ in_flight_or_done)
  end

  @spec prune(t(), Candidate.t()) :: t()
  def prune(checklist, local_cand) do
    checklist
    |> Enum.reject(fn {_pair_id, pair} -> pair.local_cand_id == local_cand.base.id end)
    |> Map.new()
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
end
