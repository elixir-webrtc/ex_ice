defmodule ExICE.CandidateTest do
  use ExUnit.Case, async: true

  alias ExICE.Candidate

  test "candidate's foundation" do
    ip = {192, 168, 1, 1}
    port = 12_345

    %Candidate{foundation: f1} =
      Candidate.new(:host, address: ip, port: port, base_address: ip, base_port: port)

    %Candidate{foundation: f2} =
      Candidate.new(:host, address: ip, port: port, base_address: ip, base_port: port)

    assert f1 == f2

    ip2 = {192, 168, 1, 2}
    port2 = 23_456

    %Candidate{foundation: f1} =
      Candidate.new(:host, address: ip, port: port, base_address: ip, base_port: port)

    %Candidate{foundation: f2} =
      Candidate.new(:host, address: ip2, port: port2, base_address: ip2, base_port: port2)

    assert f1 != f2
  end

  test "marshal/1" do
    ip = {192, 168, 1, 1}
    port = 12_345
    expected_m_c = "936255739 1 UDP 1234 192.168.1.1 12345 typ host"

    c =
      Candidate.new(:host,
        address: ip,
        port: port,
        base_address: ip,
        base_port: port,
        priority: 1234,
        transport_module: nil
      )

    m_c = Candidate.marshal(c)

    assert m_c == expected_m_c
  end

  test "unmarshal/1" do
    ip = {192, 168, 1, 1}
    port = 12_345
    m_c = "936255739 1 UDP 1234 192.168.1.1 12345 typ host"

    expected_c =
      Candidate.new(:host, address: ip, port: port, priority: 1234, transport_module: nil)

    assert {:ok, c} = Candidate.unmarshal(m_c)
    c = %Candidate{c | id: expected_c.id}
    assert c == expected_c
  end
end
