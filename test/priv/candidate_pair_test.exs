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
        socket: nil,
        transport_module: ExICE.Support.Transport.Mock
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

  test "schedule_keepalive/2 randomizes the interval by +/-20%" do
    c1 =
      Candidate.Host.new(
        address: {192, 168, 1, 1},
        port: 12_345,
        base_address: {192, 168, 1, 1},
        base_port: 12_345,
        priority: 100,
        socket: nil,
        transport_module: ExICE.Support.Transport.Mock
      )

    c2 = ExICE.Candidate.new(:host, address: {192, 168, 1, 2}, port: 23_456, priority: 200)
    pair = CandidatePair.new(c1, c2, :controlling, :succeeded)

    timeouts =
      for _ <- 1..50 do
        pair = CandidatePair.schedule_keepalive(pair, 1_000)
        remaining = Process.read_timer(pair.keepalive_timer)
        Process.cancel_timer(pair.keepalive_timer)
        remaining
      end

    assert Enum.all?(timeouts, &(&1 >= 790 and &1 <= 1_200))
    assert length(Enum.uniq(timeouts)) > 1
  end

  test "schedule_keepalive/2 cancels the previous timer" do
    c1 =
      Candidate.Host.new(
        address: {192, 168, 1, 1},
        port: 12_345,
        base_address: {192, 168, 1, 1},
        base_port: 12_345,
        priority: 100,
        socket: nil,
        transport_module: ExICE.Support.Transport.Mock
      )

    c2 = ExICE.Candidate.new(:host, address: {192, 168, 1, 2}, port: 23_456, priority: 200)
    pair = CandidatePair.new(c1, c2, :controlling, :succeeded)

    old_pair = CandidatePair.schedule_keepalive(pair, 1_000)
    new_pair = CandidatePair.schedule_keepalive(old_pair, 1_000)

    assert Process.read_timer(old_pair.keepalive_timer) == false
    assert is_integer(Process.read_timer(new_pair.keepalive_timer))
  end
end
