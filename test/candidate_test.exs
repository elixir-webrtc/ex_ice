defmodule ExICE.CandidateTest do
  use ExUnit.Case, async: true

  alias ExICE.Candidate

  test "candidate's foundation" do
    ip = {192, 168, 1, 1}
    port = 12_345

    %Candidate{foundation: f1} =
      Candidate.new(:host,
        address: ip,
        port: port,
        base_address: ip,
        base_port: port,
        priority: 123
      )

    %Candidate{foundation: f2} =
      Candidate.new(:host,
        address: ip,
        port: port,
        base_address: ip,
        base_port: port,
        priority: 123
      )

    assert f1 == f2

    ip2 = {192, 168, 1, 2}
    port2 = 23_456

    %Candidate{foundation: f1} =
      Candidate.new(:host,
        address: ip,
        port: port,
        base_address: ip,
        base_port: port,
        priority: 123
      )

    %Candidate{foundation: f2} =
      Candidate.new(:host,
        address: ip2,
        port: port2,
        base_address: ip2,
        base_port: port2,
        priority: 122
      )

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

  test "unmarshal/1 with string foundation" do
    m_c = "834be7808a5c955b681935b0c6ad99df 1 UDP 2130706431 192.168.1.74 55474 typ host"

    assert {:ok, c} = Candidate.unmarshal(m_c)
    assert c.foundation == "834be7808a5c955b681935b0c6ad99df"
    assert c.address == {192, 168, 1, 74}
    assert c.port == 55_474
    assert c.priority == 2_130_706_431
    assert c.type == :host
    assert c.transport == :udp
  end

  test "unmarshal/1 preserves numeric foundation as string" do
    m_c = "936255739 1 UDP 1234 192.168.1.1 12345 typ host"

    assert {:ok, c} = Candidate.unmarshal(m_c)
    assert c.foundation == "936255739"
    assert is_binary(c.foundation)
  end

  test "unmarshal/1 rejects candidate with leading space (empty foundation)" do
    m_c = " 1 UDP 1234 192.168.1.1 12345 typ host"
    assert {:error, :invalid_foundation} = Candidate.unmarshal(m_c)
  end

  test "unmarshal/1 accepts foundation of exactly 32 characters" do
    foundation = String.duplicate("a", 32)
    m_c = "#{foundation} 1 UDP 1234 192.168.1.1 12345 typ host"
    assert {:ok, c} = Candidate.unmarshal(m_c)
    assert c.foundation == foundation
  end

  test "unmarshal/1 accepts single character foundation" do
    m_c = "a 1 UDP 1234 192.168.1.1 12345 typ host"
    assert {:ok, c} = Candidate.unmarshal(m_c)
    assert c.foundation == "a"
  end

  test "unmarshal/1 rejects foundation longer than 32 characters" do
    long_foundation = String.duplicate("a", 33)
    m_c = "#{long_foundation} 1 UDP 1234 192.168.1.1 12345 typ host"
    assert {:error, :invalid_foundation} = Candidate.unmarshal(m_c)
  end

  test "unmarshal/1 rejects foundation with invalid characters" do
    m_c = "abc!@#def 1 UDP 1234 192.168.1.1 12345 typ host"
    assert {:error, :invalid_foundation} = Candidate.unmarshal(m_c)
  end

  test "unmarshal/1 preserves foundation with leading zeros" do
    m_c = "001 1 UDP 1234 192.168.1.1 12345 typ host"

    assert {:ok, c} = Candidate.unmarshal(m_c)
    assert c.foundation == "001"
    assert Candidate.marshal(c) == m_c
  end

  test "unmarshal/1 preserves foundation with plus and slash" do
    m_c = "abc+/def 1 UDP 1234 192.168.1.1 12345 typ host"

    assert {:ok, c} = Candidate.unmarshal(m_c)
    assert c.foundation == "abc+/def"
    assert Candidate.marshal(c) == m_c
  end

  test "marshal/1 roundtrips with string foundation" do
    m_c = "834be7808a5c955b681935b0c6ad99df 1 UDP 2130706431 192.168.1.74 55474 typ host"

    assert {:ok, c} = Candidate.unmarshal(m_c)
    assert Candidate.marshal(c) == m_c
  end
end
