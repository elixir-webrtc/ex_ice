defmodule ExIce.CandidateTest do
  use ExUnit.Case

  alias ExIce.Candidate

  test "candidate's foundation is calculated correctly" do
    # FIXME socket shouldn't be nil
    ip = {192, 168, 1, 1}
    port = 12345
    %Candidate{foundation: f1} = Candidate.new(:host, ip, port, ip, port, nil)
    %Candidate{foundation: f2} = Candidate.new(:host, ip, port, ip, port, nil)
    assert f1 == f2

    ip2 = {192, 168, 1, 2}
    port2 = 23456
    %Candidate{foundation: f1} = Candidate.new(:host, ip, port, ip, port, nil)
    %Candidate{foundation: f2} = Candidate.new(:host, ip2, port2, ip2, port2, nil)
    assert f1 != f2
  end

  test "marshal returns correct candidate string representation" do
    ip = {192, 168, 1, 1}
    port = 12345
    expected_m_c = "936255739 1 UDP 0 192.168.1.1 12345 typ host"

    c = Candidate.new(:host, ip, port, ip, port, nil)
    m_c = Candidate.marshal(c)

    assert m_c == expected_m_c
  end
end
