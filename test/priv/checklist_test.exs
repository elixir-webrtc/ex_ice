defmodule ExICE.Priv.ChecklistTest do
  use ExUnit.Case, async: true

  alias ExICE.Priv.{Candidate, CandidatePair, Checklist}

  test "get_valid_pair/1" do
    local_addr = {192, 168, 0, 1}
    local_port = 8445
    remote_addr = {192, 168, 0, 2}
    remote_port = 8445
    remote_srflx_addr = {192, 168, 0, 3}
    remote_srflx_port = 8445

    local_host_cand =
      Candidate.Host.new(
        address: local_addr,
        port: local_port,
        base_address: local_addr,
        base_port: local_port,
        priority: 123,
        socket: nil,
        transport_module: ExICE.Support.Transport.Mock
      )

    remote_host_cand =
      ExICE.Candidate.new(:host,
        address: local_addr,
        port: local_port,
        base_address: local_addr,
        base_port: local_port,
        priority: 123
      )

    remote_srflx_cand =
      ExICE.Candidate.new(:srflx,
        address: remote_srflx_addr,
        port: remote_srflx_port,
        base_address: remote_addr,
        base_port: remote_port,
        priority: 122
      )

    host_pair =
      CandidatePair.new(local_host_cand, remote_host_cand, :controlling, :succeeded, valid?: true)

    srflx_pair =
      CandidatePair.new(local_host_cand, remote_srflx_cand, :controlling, :succeeded,
        valid?: true
      )

    checklist = %{host_pair.id => host_pair, srflx_pair.id => srflx_pair}

    assert host_pair.priority > srflx_pair.priority
    assert Checklist.get_valid_pair(checklist) == host_pair
  end
end
