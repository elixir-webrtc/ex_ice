defmodule ExICE.Priv.CandidateTest do
  use ExUnit.Case, async: true

  alias ExICE.Priv.Candidate

  test "priority/4" do
    base_addr = {192, 168, 0, 1}

    ## UDP and general behaviour

    {prefs, prio_host_udp} = Candidate.priority(%{}, base_addr, :host, nil)

    assert map_size(prefs) == 1
    assert Map.has_key?(prefs, base_addr)

    # is idempotent
    {^prefs, ^prio_host_udp} = Candidate.priority(prefs, base_addr, :host, nil)

    base_addr2 = {192, 168, 0, 2}
    {prefs, prio_host_udp_2} = Candidate.priority(prefs, base_addr2, :host, nil)
    assert map_size(prefs) == 2
    assert Map.has_key?(prefs, base_addr)
    assert Map.has_key?(prefs, base_addr2)
    assert prio_host_udp != prio_host_udp_2

    # the same base address that created srflx candidate
    {^prefs, prio_srflx_udp} = Candidate.priority(prefs, base_addr, :srflx, nil)
    assert prio_srflx_udp < prio_host_udp
    assert prio_srflx_udp < prio_host_udp_2

    # the same base address that created relay candidate
    {^prefs, prio_relay_udp} = Candidate.priority(prefs, base_addr, :relay, nil)
    assert prio_relay_udp < prio_srflx_udp

    # the same base address that created prflx candidate
    {^prefs, prio_prflx_udp} = Candidate.priority(prefs, base_addr, :prflx, nil)
    assert prio_prflx_udp < prio_host_udp
    assert prio_prflx_udp < prio_host_udp_2
    assert prio_prflx_udp > prio_relay_udp

    ## TCP

    {prefs, prio_host_active} = Candidate.priority(prefs, base_addr, :host, :active)
    {prefs, prio_host_passive} = Candidate.priority(prefs, base_addr, :host, :passive)
    {prefs, prio_host_so} = Candidate.priority(prefs, base_addr, :host, :so)
    {prefs, prio_srflx_so} = Candidate.priority(prefs, base_addr, :srflx, :so)
    {prefs, prio_srflx_active} = Candidate.priority(prefs, base_addr, :srflx, :active)
    {prefs, prio_srflx_passive} = Candidate.priority(prefs, base_addr, :srflx, :passive)
    {prefs, prio_relay_so} = Candidate.priority(prefs, base_addr, :relay, :so)
    {prefs, prio_relay_active} = Candidate.priority(prefs, base_addr, :relay, :active)
    {prefs, prio_relay_passive} = Candidate.priority(prefs, base_addr, :relay, :passive)
    {prefs, prio_prflx_so} = Candidate.priority(prefs, base_addr, :prflx, :so)
    {prefs, prio_prflx_active} = Candidate.priority(prefs, base_addr, :prflx, :active)
    {_prefs, prio_prflx_passive} = Candidate.priority(prefs, base_addr, :prflx, :passive)

    # Direction preference
    # For :host, :udp_tunneled, :relay -> Active (6) > Passive (4) > SO (2)
    assert prio_host_active > prio_host_passive
    assert prio_host_passive > prio_host_so

    assert prio_relay_active > prio_relay_passive
    assert prio_relay_passive > prio_relay_so

    # For :srflx, :prfix, :nat_assisted -> SO (6) > Active (4) > Passive (2)
    assert prio_srflx_so > prio_srflx_active
    assert prio_srflx_active > prio_srflx_passive

    assert prio_prflx_so > prio_prflx_active
    assert prio_prflx_active > prio_prflx_passive

    # Type preference
    assert prio_host_so > prio_srflx_so
    assert prio_host_so > prio_prflx_so

    assert prio_srflx_passive > prio_relay_active
    assert prio_prflx_passive > prio_relay_active

    ## UDP + TCP currently planned behaviour

    # Prefer UDP host, prflx, srflx over TCP
    assert prio_host_udp > prio_host_active
    assert prio_prflx_udp > prio_host_active
    assert prio_srflx_udp > prio_host_active

    # Prefer UDP relay over TCP relay
    assert prio_relay_udp > prio_relay_active

    # Prefer TCP host, prflx, srflx over relay
    assert prio_host_so > prio_relay_udp
    assert prio_prflx_passive > prio_relay_udp
    assert prio_srflx_passive > prio_relay_udp
  end
end
