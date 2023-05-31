defmodule ExICE.GathererTest do
  use ExUnit.Case

  alias ExICE.Candidate
  alias ExICE.Gatherer

  test "gather host candidates" do
    {:ok, cands} = Gatherer.gather_host_candidates()
    assert cands != []
    assert Enum.all?(cands, &match?(%Candidate{}, &1))
  end
end
