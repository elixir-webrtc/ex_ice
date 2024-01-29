defmodule ExICE.ICEAgentTest do
  use ExUnit.Case

  alias ExICE.ICEAgent

  test "gather_candidates/1" do
    {:ok, agent} = ICEAgent.start_link(:controlling)
    :ok = ICEAgent.gather_candidates(agent)

    assert_receive {:ex_ice, ^agent, {:gathering_state_change, :gathering}}
    assert_receive {:ex_ice, ^agent, {:gathering_state_change, :complete}}

    :ok = ICEAgent.restart(agent)
    assert_receive {:ex_ice, ^agent, {:gathering_state_change, :new}}

    :ok = ICEAgent.gather_candidates(agent)
    assert_receive {:ex_ice, ^agent, {:gathering_state_change, :gathering}}
    assert_receive {:ex_ice, ^agent, {:gathering_state_change, :complete}}
  end

  test "get_stats/1" do
    {:ok, agent} = ICEAgent.start_link(:controlling)

    assert %{
             bytes_sent: 0,
             bytes_received: 0,
             packets_sent: 0,
             packets_received: 0,
             state: :new,
             role: :controlling,
             local_ufrag: local_ufrag,
             local_candidates: [],
             remote_candidates: [],
             candidate_pairs: candidate_pairs
           } =
             ICEAgent.get_stats(agent)

    assert is_list(candidate_pairs)
    assert is_binary(local_ufrag)
  end
end
