defmodule ExICE.Integration.P2PTest do
  use ExUnit.Case

  alias ExICE.ICEAgent

  @tag :p2p
  test "P2P connection" do
    stun_servers = ["stun:stun.l.google.com:19302"]

    ip_filter = fn
      {_, _, _, _, _, _, _, _} -> true
      {172, 17, 0, 1} -> true
      _other -> true
    end

    {:ok, agent1} =
      ICEAgent.start_link(:controlling, ip_filter: ip_filter, stun_servers: stun_servers)

    {:ok, agent2} =
      ICEAgent.start_link(:controlled, ip_filter: ip_filter, stun_servers: stun_servers)

    ICEAgent.run(agent1)
    ICEAgent.run(agent2)

    assert p2p(agent1, agent2)
  end

  defp p2p(agent1, agent2, a1_status \\ false, a2_status \\ false)

  defp p2p(_agent1, _agent2, true, true), do: true

  defp p2p(agent1, agent2, a1_status, a2_status) do
    receive do
      {^agent1, {:new_candidate, cand}} ->
        ICEAgent.add_remote_candidate(agent2, cand)
        p2p(agent1, agent2, a1_status, a2_status)

      {^agent1, {:local_credentials, ufrag, passwd}} ->
        ICEAgent.set_remote_credentials(agent2, ufrag, passwd)
        p2p(agent1, agent2, a1_status, a2_status)

      {^agent1, :gathering_done} ->
        ICEAgent.end_of_candidates(agent2)
        p2p(agent1, agent2, a1_status, a2_status)

      {^agent1, {:selected_pair, _p}} ->
        p2p(agent1, agent2, true, a2_status)

      {^agent2, {:new_candidate, cand}} ->
        ICEAgent.add_remote_candidate(agent1, cand)
        p2p(agent1, agent2, a1_status, a2_status)

      {^agent2, {:local_credentials, ufrag, passwd}} ->
        ICEAgent.set_remote_credentials(agent1, ufrag, passwd)
        p2p(agent1, agent2, a1_status, a2_status)

      {^agent2, :gathering_done} ->
        ICEAgent.end_of_candidates(agent1)
        p2p(agent1, agent2, a1_status, a2_status)

      {^agent2, {:selected_pair, _p}} ->
        p2p(agent1, agent2, a1_status, true)
    after
      4000 -> false
    end
  end
end
