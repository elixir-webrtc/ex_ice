defmodule ExICE.Priv.CandidateTest do
  use ExUnit.Case, async: true

  alias ExICE.Priv.Candidate

  test "priority/3" do
    {local_preferences1, prio1} = Candidate.priority(%{}, {192, 168, 0, 1}, :host)

    assert map_size(local_preferences1) == 1
    assert Map.has_key?(local_preferences1, {192, 168, 0, 1})

    # is idempotent
    {^local_preferences1, ^prio1} =
      Candidate.priority(local_preferences1, {192, 168, 0, 1}, :host)

    {local_preferences2, prio2} = Candidate.priority(local_preferences1, {192, 168, 0, 2}, :host)
    assert map_size(local_preferences2) == 2
    assert Map.has_key?(local_preferences2, {192, 168, 0, 1})
    assert Map.has_key?(local_preferences2, {192, 168, 0, 2})
    assert prio2 != prio1

    # the same base address that created srflx candidate
    {^local_preferences2, prio3} =
      Candidate.priority(local_preferences2, {192, 168, 0, 1}, :srflx)

    assert prio3 < prio2
    assert prio3 < prio1

    # the same base address that created relay candidate
    {^local_preferences2, prio4} =
      Candidate.priority(local_preferences2, {192, 168, 0, 1}, :relay)

    assert prio4 < prio3

    # the same base address that created prflx candidate
    {^local_preferences2, prio5} =
      Candidate.priority(local_preferences2, {192, 168, 0, 1}, :prflx)

    assert prio5 < prio1
    assert prio5 < prio2
    assert prio5 > prio3
  end
end
