defmodule ExICE.Priv.CandidatePairTest do
  use ExUnit.Case, async: true

  alias ExICE.Priv.{Candidate, CandidatePair}

  test "new/3" do
    addr1 = {192, 168, 1, 1}
    port1 = 12_345

    c1 =
      Candidate.Host.new(
        address: addr1,
        port: port1,
        base_address: addr1,
        base_port: port1,
        priority: 100,
        socket: nil
      )

    addr2 = {192, 168, 1, 2}
    port2 = 23_456

    c2 =
      ExICE.Candidate.new(:host,
        address: addr2,
        port: port2,
        base_address: addr2,
        base_port: port2,
        priority: 200
      )

    c1c2 = CandidatePair.new(c1, c2, :controlling, :frozen)
    assert c1c2.priority == 429_496_730_000

    c2c1 = CandidatePair.new(c1, c2, :controlled, :frozen)
    assert c2c1.priority == 429_496_730_001

    assert abs(c1c2.priority - c2c1.priority) == 1
  end
end
