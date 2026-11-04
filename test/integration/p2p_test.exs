defmodule ExICE.Integration.P2PTest do
  use ExUnit.Case, async: true

  require Logger

  alias ExICE.ICEAgent

  @tag :p2p
  @tag :tmp_dir
  test "P2P connection", %{tmp_dir: tmp_dir} do
    for {transport, ice_servers} <- [
          {:udp, [%{urls: "stun:stun.l.google.com:19302"}]},
          {:tcp, [%{urls: "stun:stun.freeswitch.org:3478"}]}
        ] do
      ip_filter = fn
        {_, _, _, _, _, _, _, _} -> true
        {172, _, _, _} -> true
        _other -> true
      end

      {:ok, agent1} =
        ICEAgent.start_link(
          role: :controlling,
          ip_filter: ip_filter,
          ice_servers: ice_servers,
          transport: transport
        )

      {:ok, agent2} =
        ICEAgent.start_link(
          role: :controlled,
          ip_filter: ip_filter,
          ice_servers: [],
          transport: transport
        )

      {:ok, a1_ufrag, a1_pwd} = ICEAgent.get_local_credentials(agent1)
      {:ok, a2_ufrag, a2_pwd} = ICEAgent.get_local_credentials(agent2)

      :ok = ICEAgent.set_remote_credentials(agent2, a1_ufrag, a1_pwd)
      :ok = ICEAgent.set_remote_credentials(agent1, a2_ufrag, a2_pwd)

      :ok = ICEAgent.gather_candidates(agent1)
      :ok = ICEAgent.gather_candidates(agent2)

      assert_receive {:ex_ice, ^agent1, {:gathering_state_change, :gathering}}
      assert_receive {:ex_ice, ^agent2, {:gathering_state_change, :gathering}}

      a1_fd = File.open!(Path.join([tmp_dir, "a1_recv_data"]), [:append])
      a2_fd = File.open!(Path.join([tmp_dir, "a2_recv_data"]), [:append])

      a1_status = %{fd: a1_fd, data_send: false, completed: false, data_recv: false}
      a2_status = %{fd: a2_fd, data_send: false, completed: false, data_recv: false}

      assert p2p(agent1, agent2, a1_status, a2_status)

      assert File.read!(Path.join([tmp_dir, "a1_recv_data"])) ==
               File.read!("./test/fixtures/lotr.txt")

      assert File.read!(Path.join([tmp_dir, "a2_recv_data"])) ==
               File.read!("./test/fixtures/lotr.txt")

      :ok = File.close(a1_fd)
      :ok = File.close(a2_fd)

      a1_fd = File.open!(Path.join([tmp_dir, "a1_restart_recv_data"]), [:append])
      a2_fd = File.open!(Path.join([tmp_dir, "a2_restart_recv_data"]), [:append])

      a1_status = %{fd: a1_fd, data_send: false, completed: false, data_recv: false}
      a2_status = %{fd: a2_fd, data_send: false, completed: false, data_recv: false}

      flush_ice_mailbox()

      :ok = ICEAgent.restart(agent1)
      {:ok, a1_ufrag, a1_pwd} = ICEAgent.get_local_credentials(agent1)
      :ok = ICEAgent.set_remote_credentials(agent2, a1_ufrag, a1_pwd)
      {:ok, a2_ufrag, a2_pwd} = ICEAgent.get_local_credentials(agent2)
      :ok = ICEAgent.set_remote_credentials(agent1, a2_ufrag, a2_pwd)

      assert_receive {:ex_ice, ^agent1, {:gathering_state_change, :new}}
      assert_receive {:ex_ice, ^agent1, {:connection_state_change, :checking}}
      assert_receive {:ex_ice, ^agent2, {:gathering_state_change, :new}}
      assert_receive {:ex_ice, ^agent2, {:connection_state_change, :checking}}

      :ok = ICEAgent.gather_candidates(agent1)
      :ok = ICEAgent.gather_candidates(agent2)

      assert p2p(agent1, agent2, a1_status, a2_status)

      assert File.read!(Path.join([tmp_dir, "a1_restart_recv_data"])) ==
               File.read!("./test/fixtures/lotr.txt")

      assert File.read!(Path.join([tmp_dir, "a2_restart_recv_data"])) ==
               File.read!("./test/fixtures/lotr.txt")

      assert :ok = ICEAgent.close(agent1)
      assert :ok = ICEAgent.close(agent2)

      assert :ok = ICEAgent.stop(agent1)
      assert :ok = ICEAgent.stop(agent2)

      File.rm(Path.join([tmp_dir, "a1_recv_data"]))
      File.rm(Path.join([tmp_dir, "a2_recv_data"]))
      File.rm(Path.join([tmp_dir, "a1_restart_recv_data"]))
      File.rm(Path.join([tmp_dir, "a2_restart_recv_data"]))
    end
  end

  @tag :tmp_dir
  @tag :role_conflict
  test "P2P connection with role conflict", %{tmp_dir: tmp_dir} do
    for {transport, ice_servers} <- [
          {:udp, [%{urls: "stun:stun.l.google.com:19302"}]},
          {:tcp, [%{urls: "stun:stun.freeswitch.org:3478"}]}
        ] do
      ip_filter = fn
        {_, _, _, _, _, _, _, _} -> true
        {172, _, _, _} -> true
        _other -> true
      end

      {:ok, agent1} =
        ICEAgent.start_link(
          role: :controlled,
          ip_filter: ip_filter,
          ice_servers: ice_servers,
          transport: transport
        )

      {:ok, agent2} =
        ICEAgent.start_link(
          role: :controlled,
          ip_filter: ip_filter,
          ice_servers: ice_servers,
          transport: transport
        )

      {:ok, a1_ufrag, a1_pwd} = ICEAgent.get_local_credentials(agent1)
      {:ok, a2_ufrag, a2_pwd} = ICEAgent.get_local_credentials(agent2)

      :ok = ICEAgent.set_remote_credentials(agent2, a1_ufrag, a1_pwd)
      :ok = ICEAgent.set_remote_credentials(agent1, a2_ufrag, a2_pwd)

      :ok = ICEAgent.gather_candidates(agent1)
      :ok = ICEAgent.gather_candidates(agent2)

      a1_fd = File.open!(Path.join([tmp_dir, "a1_recv_data"]), [:append])
      a2_fd = File.open!(Path.join([tmp_dir, "a2_recv_data"]), [:append])

      a1_status = %{fd: a1_fd, data_send: false, completed: false, data_recv: false}
      a2_status = %{fd: a2_fd, data_send: false, completed: false, data_recv: false}

      assert p2p(agent1, agent2, a1_status, a2_status)

      assert File.read!(Path.join([tmp_dir, "a1_recv_data"])) ==
               File.read!("./test/fixtures/lotr.txt")

      assert File.read!(Path.join([tmp_dir, "a2_recv_data"])) ==
               File.read!("./test/fixtures/lotr.txt")

      File.rm(Path.join([tmp_dir, "a1_recv_data"]))
      File.rm(Path.join([tmp_dir, "a2_recv_data"]))
    end
  end

  @tag :tmp_dir
  @tag :relay
  test "P2P connection via turn server", %{tmp_dir: tmp_dir} do
    # This test is by default excluded from runinng.
    # Before running, start coturn with: turnserver -a -u testusername:testpassword

    ice_servers = [
      %{
        urls: "turn:127.0.0.1:3478?transport=udp",
        username: "testusername",
        credential: "testpassword"
      }
    ]

    ip_filter = fn
      {_, _, _, _, _, _, _, _} -> true
      {172, _, _, _} -> true
      _other -> true
    end

    {:ok, agent1} =
      ICEAgent.start_link(
        role: :controlling,
        ip_filter: ip_filter,
        ice_servers: ice_servers,
        ice_transport_policy: :relay
      )

    {:ok, agent2} =
      ICEAgent.start_link(role: :controlled, ip_filter: ip_filter, ice_servers: [])

    {:ok, a1_ufrag, a1_pwd} = ICEAgent.get_local_credentials(agent1)
    {:ok, a2_ufrag, a2_pwd} = ICEAgent.get_local_credentials(agent2)

    :ok = ICEAgent.set_remote_credentials(agent2, a1_ufrag, a1_pwd)
    :ok = ICEAgent.set_remote_credentials(agent1, a2_ufrag, a2_pwd)

    :ok = ICEAgent.gather_candidates(agent1)
    :ok = ICEAgent.gather_candidates(agent2)

    a1_fd = File.open!(Path.join([tmp_dir, "a1_recv_data"]), [:append])
    a2_fd = File.open!(Path.join([tmp_dir, "a2_recv_data"]), [:append])

    a1_status = %{fd: a1_fd, data_send: false, completed: false, data_recv: false}
    a2_status = %{fd: a2_fd, data_send: false, completed: false, data_recv: false}

    assert p2p(agent1, agent2, a1_status, a2_status)

    assert File.read!(Path.join([tmp_dir, "a1_recv_data"])) ==
             File.read!("./test/fixtures/lotr.txt")

    assert File.read!(Path.join([tmp_dir, "a2_recv_data"])) ==
             File.read!("./test/fixtures/lotr.txt")
  end

  @liveness_opts [disconnected_timeout: 300, failed_timeout: 1_500, keepalive_interval: 100]

  @tag :p2p
  test "disconnected state" do
    {agent1, agent2} = start_and_connect(@liveness_opts)

    # agent2 stops processing anything, including agent1's keepalives
    :ok = :sys.suspend(agent2)
    assert_receive {:ex_ice, ^agent1, {:connection_state_change, :disconnected}}, 1_000

    # agent1 can still send, and recovers once agent2 is back
    :ok = ICEAgent.send_data(agent1, "while disconnected")
    :ok = :sys.resume(agent2)
    assert_receive {:ex_ice, ^agent1, {:connection_state_change, :completed}}, 1_000
    assert_receive {:ex_ice, ^agent2, {:data, "while disconnected"}}, 1_000

    :ok = ICEAgent.send_data(agent1, "after recovery")
    assert_receive {:ex_ice, ^agent2, {:data, "after recovery"}}, 1_000
    refute_received {:ex_ice, ^agent1, {:connection_state_change, :failed}}

    :ok = ICEAgent.stop(agent1)
    :ok = ICEAgent.stop(agent2)
  end

  @tag :p2p
  test "restart from failed state" do
    {agent1, agent2} = start_and_connect(@liveness_opts)
    fail_and_restart(agent1, agent2)

    :ok = ICEAgent.stop(agent1)
    :ok = ICEAgent.stop(agent2)
  end

  @tag :relay
  test "restart from failed state via turn server" do
    # This test is by default excluded from runinng.
    # Before running, start coturn with: turnserver -a -u testusername:testpassword
    ice_servers = [
      %{
        urls: "turn:127.0.0.1:3478?transport=udp",
        username: "testusername",
        credential: "testpassword"
      }
    ]

    agent1_opts = [ice_servers: ice_servers, ice_transport_policy: :relay] ++ @liveness_opts
    {agent1, agent2} = start_and_connect(agent1_opts, @liveness_opts)
    fail_and_restart(agent1, agent2)

    :ok = ICEAgent.stop(agent1)
    :ok = ICEAgent.stop(agent2)
  end

  defp fail_and_restart(agent1, agent2) do
    # agent2 stops processing anything for longer than failed_timeout
    :ok = :sys.suspend(agent2)
    assert_receive {:ex_ice, ^agent1, {:connection_state_change, :failed}}, 3_000
    :ok = :sys.resume(agent2)
    # agent1 has closed its sockets, so agent2 fails too
    assert_receive {:ex_ice, ^agent2, {:connection_state_change, :failed}}, 3_000
    flush_ice_mailbox()

    # failed agents can be restarted
    :ok = ICEAgent.restart(agent1)
    {:ok, a1_ufrag, a1_pwd} = ICEAgent.get_local_credentials(agent1)
    :ok = ICEAgent.set_remote_credentials(agent2, a1_ufrag, a1_pwd)
    {:ok, a2_ufrag, a2_pwd} = ICEAgent.get_local_credentials(agent2)
    :ok = ICEAgent.set_remote_credentials(agent1, a2_ufrag, a2_pwd)

    assert_receive {:ex_ice, ^agent1, {:connection_state_change, :checking}}
    assert_receive {:ex_ice, ^agent2, {:connection_state_change, :checking}}

    :ok = ICEAgent.gather_candidates(agent1)
    :ok = ICEAgent.gather_candidates(agent2)
    assert connect(agent1, agent2, {false, false})

    :ok = ICEAgent.send_data(agent1, "from agent1")
    :ok = ICEAgent.send_data(agent2, "from agent2")
    assert_receive {:ex_ice, ^agent2, {:data, "from agent1"}}, 1_000
    assert_receive {:ex_ice, ^agent1, {:data, "from agent2"}}, 1_000
  end

  defp start_and_connect(agent1_opts, agent2_opts \\ nil) do
    ip_filter = fn
      {_, _, _, _} -> true
      _other -> false
    end

    agent2_opts = agent2_opts || agent1_opts

    {:ok, agent1} = ICEAgent.start_link([role: :controlling, ip_filter: ip_filter] ++ agent1_opts)
    {:ok, agent2} = ICEAgent.start_link([role: :controlled, ip_filter: ip_filter] ++ agent2_opts)

    {:ok, a1_ufrag, a1_pwd} = ICEAgent.get_local_credentials(agent1)
    {:ok, a2_ufrag, a2_pwd} = ICEAgent.get_local_credentials(agent2)

    :ok = ICEAgent.set_remote_credentials(agent2, a1_ufrag, a1_pwd)
    :ok = ICEAgent.set_remote_credentials(agent1, a2_ufrag, a2_pwd)

    :ok = ICEAgent.gather_candidates(agent1)
    :ok = ICEAgent.gather_candidates(agent2)

    assert connect(agent1, agent2, {false, false})
    {agent1, agent2}
  end

  defp connect(_agent1, _agent2, {true, true}), do: true

  defp connect(agent1, agent2, {a1_completed?, a2_completed?} = completed) do
    receive do
      {:ex_ice, ^agent1, {:new_candidate, cand}} ->
        :ok = ICEAgent.add_remote_candidate(agent2, cand)
        connect(agent1, agent2, completed)

      {:ex_ice, ^agent2, {:new_candidate, cand}} ->
        :ok = ICEAgent.add_remote_candidate(agent1, cand)
        connect(agent1, agent2, completed)

      {:ex_ice, ^agent1, {:gathering_state_change, :complete}} ->
        :ok = ICEAgent.end_of_candidates(agent2)
        connect(agent1, agent2, completed)

      {:ex_ice, ^agent2, {:gathering_state_change, :complete}} ->
        :ok = ICEAgent.end_of_candidates(agent1)
        connect(agent1, agent2, completed)

      {:ex_ice, ^agent1, {:connection_state_change, :completed}} ->
        connect(agent1, agent2, {true, a2_completed?})

      {:ex_ice, ^agent2, {:connection_state_change, :completed}} ->
        connect(agent1, agent2, {a1_completed?, true})

      {:ex_ice, _agent, _msg} ->
        connect(agent1, agent2, completed)
    after
      5_000 -> false
    end
  end

  defp p2p(_agent1, _agent2, %{completed: true, data_recv: true}, %{
         completed: true,
         data_recv: true
       }),
       do: true

  defp p2p(agent1, agent2, a1_status, a2_status) do
    receive do
      {:ex_ice, ^agent1, {:new_candidate, cand}} ->
        ICEAgent.add_remote_candidate(agent2, cand)
        p2p(agent1, agent2, a1_status, a2_status)

      {:ex_ice, ^agent1, {:gathering_state_change, :complete}} ->
        ICEAgent.end_of_candidates(agent2)
        p2p(agent1, agent2, a1_status, a2_status)

      {:ex_ice, ^agent1, {:connection_state_change, new_state}} ->
        Logger.info("Conn state change: #{inspect(new_state)}")

        a1_status =
          if new_state in [:connected, :completed] and not a1_status.data_send do
            Logger.info("Sending file...")

            Task.start(fn ->
              File.stream!("./test/fixtures/lotr.txt", 1000, [])
              |> Stream.each(fn chunk -> ICEAgent.send_data(agent1, chunk) end)
              |> Stream.run()

              ICEAgent.send_data(agent1, "eof")
            end)

            %{a1_status | data_send: true}
          else
            a1_status
          end

        a1_status = %{a1_status | completed: new_state == :completed}
        p2p(agent1, agent2, a1_status, a2_status)

      {:ex_ice, ^agent1, {:data, "eof"}} ->
        p2p(agent1, agent2, %{a1_status | data_recv: true}, a2_status)

      {:ex_ice, ^agent1, {:data, data}} ->
        :ok = IO.binwrite(a1_status.fd, data)
        p2p(agent1, agent2, a1_status, a2_status)

      {:ex_ice, ^agent2, {:new_candidate, cand}} ->
        ICEAgent.add_remote_candidate(agent1, cand)
        p2p(agent1, agent2, a1_status, a2_status)

      {:ex_ice, ^agent2, {:gathering_state_change, :complete}} ->
        ICEAgent.end_of_candidates(agent1)
        p2p(agent1, agent2, a1_status, a2_status)

      {:ex_ice, ^agent2, {:connection_state_change, new_state}} ->
        Logger.info("Conn state change: #{inspect(new_state)}")

        a2_status =
          if new_state in [:connected, :completed] and not a2_status.data_send do
            Logger.info("Sending file...")

            Task.start(fn ->
              File.stream!("./test/fixtures/lotr.txt", 1000, [])
              |> Stream.each(fn chunk -> ICEAgent.send_data(agent2, chunk) end)
              |> Stream.run()

              ICEAgent.send_data(agent2, "eof")
            end)

            %{a2_status | data_send: true}
          else
            a2_status
          end

        a2_status = %{a2_status | completed: new_state == :completed}
        p2p(agent1, agent2, a1_status, a2_status)

      {:ex_ice, ^agent2, {:data, "eof"}} ->
        p2p(agent1, agent2, a1_status, %{a2_status | data_recv: true})

      {:ex_ice, ^agent2, {:data, data}} ->
        :ok = IO.binwrite(a2_status.fd, data)
        p2p(agent1, agent2, a1_status, a2_status)
    after
      20_000 -> false
    end
  end

  defp flush_ice_mailbox() do
    receive do
      {:ex_ice, _, _} -> flush_ice_mailbox()
    after
      0 -> :ok
    end
  end
end
