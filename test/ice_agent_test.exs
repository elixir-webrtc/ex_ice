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

    assert %{bytes_sent: 0, bytes_received: 0, candidate_pairs: candidate_pairs} =
             ICEAgent.get_stats(agent)

    assert is_list(candidate_pairs)
  end
end
