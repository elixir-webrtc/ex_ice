defmodule ExICE.Checklist do
  @moduledoc false

  alias ExICE.CandidatePair

  def get_next_pair(checklist) do
    checklist
    |> Enum.filter(fn {_id, pair} -> pair.state == :waiting end)
    |> Enum.max_by(fn {_id, pair} -> pair.priority end, fn -> {nil, nil} end)
    |> elem(1)
  end

  def get_pair_for_nomination(checklist) do
    checklist
    |> Enum.filter(fn {_id, pair} -> pair.valid? end)
    |> Enum.max_by(fn {_id, pair} -> pair.priority end, fn -> {nil, nil} end)
    |> elem(1)
  end

  def get_valid_pair(checklist) do
    checklist
    |> Enum.find({nil, nil}, fn {_id, pair} -> pair.valid? end)
    |> elem(1)
  end

  def find_pair(checklist, pair) do
    find_pair(checklist, pair.local_cand, pair.remote_cand)
  end

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

  def waiting?(checklist) do
    Enum.any?(checklist, fn {_id, pair} -> pair.state == :waiting end)
  end

  def in_progress?(checklist) do
    Enum.any?(checklist, fn {_id, pair} -> pair.state == :in_progress end)
  end

  def get_foundations(checklist) do
    for {_id, pair} <- checklist do
      {pair.local_cand.foundation, pair.remote_cand.foundation}
    end
  end

  def prune(checklist) do
    # uniq_by keeps first occurence of a term
    # so we need to sort checklist at first

    # TODO this still needs to be revisited:
    # a new pair might be redundant
    # but we won't prune it as we filter out
    # in flight pairs

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

  def timeout_pairs(checklist, ids) do
    for {_id, pair} <- checklist, into: %{} do
      if pair.id in ids do
        {pair.id, %CandidatePair{pair | state: :failed}}
      else
        {pair.id, pair}
      end
    end
  end
end
