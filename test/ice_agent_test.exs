defmodule ExICE.ICEAgentTest do
  use ExUnit.Case, async: true

  alias ExICE.ICEAgent

  test "get_role/1" do
    {:ok, agent} = ICEAgent.start_link(role: :controlling)
    assert ICEAgent.get_role(agent) == :controlling
  end

  test "set_role/2" do
    {:ok, agent} = ICEAgent.start_link()
    assert ICEAgent.get_role(agent) == nil
    assert :ok == ICEAgent.set_role(agent, :controlling)
    assert ICEAgent.get_role(agent) == :controlling
  end

  test "gather_candidates/1" do
    for transport <- [:udp, :tcp] do
      {:ok, agent} = ICEAgent.start_link(role: :controlling, transport: transport)
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

  test "get_stats/1" do
    {:ok, agent} = ICEAgent.start_link(role: :controlling)

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

  describe "parent crash teardown" do
    test "traps exits so terminate/2 can run TURN teardown" do
      {:ok, agent} = ICEAgent.start_link(role: :controlling)

      assert {:trap_exit, true} = Process.info(agent, :trap_exit)
    end

    test "stops when a linked process dies" do
      test_pid = self()

      owner =
        spawn(fn ->
          {:ok, agent} = ICEAgent.start_link(role: :controlling)
          send(test_pid, {:agent, agent})

          receive do
            :die -> exit(:boom)
          end
        end)

      agent =
        receive do
          {:agent, a} -> a
        after
          1_000 -> flunk("agent never started")
        end

      ref = Process.monitor(agent)
      send(owner, :die)

      assert_receive {:DOWN, ^ref, :process, ^agent, :boom}, 1_000
    end

    test "stops when a non-parent linked process dies abnormally" do
      # gen_server special-cases EXITs from the parent and bypasses
      # handle_info, so a non-parent link is needed to exercise the
      # abnormal-EXIT clause that drives terminate/2.
      # Trap exits so the agent's own EXIT signal (we're its parent) doesn't kill us.
      Process.flag(:trap_exit, true)

      {:ok, agent} = ICEAgent.start_link(role: :controlling)
      ref = Process.monitor(agent)

      spawn(fn ->
        Process.link(agent)
        exit(:boom)
      end)

      assert_receive {:DOWN, ^ref, :process, ^agent, :boom}, 1_000
    end
  end
end
