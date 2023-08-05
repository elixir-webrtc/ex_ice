defmodule ExICE.ICEAgentTest do
  use ExUnit.Case

  alias ExICE.ICEAgent

  test "gathering candidates" do
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
end
