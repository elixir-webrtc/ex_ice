defmodule ExICE.Checklist do
  @moduledoc false

  def get_next_pair(checklist) do
    checklist
    |> Enum.with_index()
    |> Enum.filter(fn {pair, _idx} -> pair.state == :waiting end)
    |> Enum.max_by(fn {pair, _idx} -> pair.priority end, fn -> nil end)
  end

  def get_pair_for_nomination(checklist) do
    checklist
    |> Enum.with_index()
    |> Enum.filter(fn {pair, _idx} -> pair.valid? end)
    |> Enum.max_by(fn {pair, _idx} -> pair.priority end, fn -> nil end)
  end

  def get_valid_pair(checklist) do
    Enum.find(checklist, fn pair -> pair.valid? end)
  end

  def find_pair(checklist, pair) do
    find_pair(checklist, pair.local_cand, pair.remote_cand)
  end

  def find_pair(checklist, local_cand, remote_cand) do
    # TODO which pairs are actually the same?
    checklist
    |> Enum.with_index()
    |> Enum.find(fn {p, _idx} ->
      p.local_cand.base_address == local_cand.base_address and
        p.local_cand.base_port == local_cand.base_port and
        p.local_cand.address == local_cand.address and
        p.local_cand.port == local_cand.port and
        p.remote_cand.address == remote_cand.address and
        p.remote_cand.port == remote_cand.port
    end)
  end

  def find_exact_pair(checklist, pair) do
    checklist
    |> Enum.with_index()
    |> Enum.find(fn {p, _idx} -> p == pair end)
  end

  def waiting?(checklist) do
    Enum.any?(checklist, fn pair -> pair.state == :waiting end)
  end

  def in_progress?(checklist) do
    Enum.any?(checklist, fn pair -> pair.state == :in_progress end)
  end

  def get_foundations(checklist) do
    for cand_pair <- checklist do
      {cand_pair.local_cand.foundation, cand_pair.remote_cand.foundation}
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
      Enum.split_with(checklist, fn p -> p.state in [:waiting, :frozen] end)

    waiting =
      waiting
      |> Enum.sort_by(fn p -> p.priority end, :desc)
      |> Enum.uniq_by(fn p ->
        {p.local_cand.base_address, p.local_cand.base_port, p.remote_cand}
      end)

    waiting ++ in_flight_or_done
  end
end
