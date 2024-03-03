defmodule ExICE.CandidatePairTest do
  use ExUnit.Case

  alias ExICE.{Candidate, CandidatePair}

  test "CandidatePair.new/3" do
    addr1 = {192, 168, 1, 1}
    port1 = 12_345
    c1 = Candidate.new(:host, addr1, port1, addr1, port1, nil)
    c1 = %Candidate{c1 | priority: 100}

    addr2 = {192, 168, 1, 2}
    port2 = 23_456
    c2 = Candidate.new(:host, addr2, port2, addr2, port2, nil)
    c2 = %Candidate{c2 | priority: 200}

    c1c2 = CandidatePair.new(c1, c2, :controlling, :frozen)
    assert c1c2.priority == 429_496_730_000

    c2c1 = CandidatePair.new(c1, c2, :controlled, :frozen)
    assert c2c1.priority == 429_496_730_001

    assert abs(c1c2.priority - c2c1.priority) == 1
  end
end
