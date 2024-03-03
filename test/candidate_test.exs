defmodule ExICE.CandidateTest do
  use ExUnit.Case, async: true

  alias ExICE.Candidate

  test "candidate's foundation" do
    # FIXME socket shouldn't be nil
    ip = {192, 168, 1, 1}
    port = 12_345
    %Candidate{foundation: f1} = Candidate.new(:host, ip, port, ip, port, nil)
    %Candidate{foundation: f2} = Candidate.new(:host, ip, port, ip, port, nil)
    assert f1 == f2

    ip2 = {192, 168, 1, 2}
    port2 = 23_456
    %Candidate{foundation: f1} = Candidate.new(:host, ip, port, ip, port, nil)
    %Candidate{foundation: f2} = Candidate.new(:host, ip2, port2, ip2, port2, nil)
    assert f1 != f2
  end

  test "marshal/1" do
    ip = {192, 168, 1, 1}
    port = 12_345
    expected_m_c = "936255739 1 UDP 1234 192.168.1.1 12345 typ host"

    c = Candidate.new(:host, ip, port, ip, port, nil, priority: 1234)
    m_c = Candidate.marshal(c)

    assert m_c == expected_m_c
  end

  test "unmarshal/1" do
    ip = {192, 168, 1, 1}
    port = 12_345
    m_c = "936255739 1 UDP 1234 192.168.1.1 12345 typ host"
    expected_c = Candidate.new(:host, ip, port, nil, nil, nil, priority: 1234)

    assert {:ok, c} = Candidate.unmarshal(m_c)
    c = %Candidate{c | id: expected_c.id}
    assert c == expected_c
  end
end
