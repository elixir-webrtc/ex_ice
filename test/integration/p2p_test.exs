defmodule ExICE.Integration.P2PTest do
  use ExUnit.Case

  require Logger

  alias ExICE.ICEAgent

  @tag :p2p
  @tag :tmp_dir
  test "P2P connection", %{tmp_dir: tmp_dir} do
    stun_servers = ["stun:stun.l.google.com:19302"]
    # stun_servers = []

    ip_filter = fn
      {_, _, _, _, _, _, _, _} -> true
      {172, _, _, _} -> true
      _other -> true
    end

    {:ok, agent1} =
      ICEAgent.start_link(:controlling, ip_filter: ip_filter, stun_servers: stun_servers)

    {:ok, agent2} =
      ICEAgent.start_link(:controlled, ip_filter: ip_filter, stun_servers: stun_servers)

    {:ok, a1_ufrag, a1_pwd} = ICEAgent.get_local_credentials(agent1)
    {:ok, a2_ufrag, a2_pwd} = ICEAgent.get_local_credentials(agent2)

    :ok = ICEAgent.set_remote_credentials(agent2, a1_ufrag, a1_pwd)
    :ok = ICEAgent.set_remote_credentials(agent1, a2_ufrag, a2_pwd)

    :ok = ICEAgent.gather_candidates(agent1)
    :ok = ICEAgent.gather_candidates(agent2)

    a1_fd = File.open!(Path.join([tmp_dir, "a1_recv_data"]), [:append])
    a2_fd = File.open!(Path.join([tmp_dir, "a2_recv_data"]), [:append])

    a1_status = %{fd: a1_fd, completed: false, data_recv: false}
    a2_status = %{fd: a2_fd, completed: false, data_recv: false}

    assert p2p(agent1, agent2, a1_status, a2_status)

    assert File.read!(Path.join([tmp_dir, "a1_recv_data"])) ==
             File.read!("./test/fixtures/lotr.txt")

    assert File.read!(Path.join([tmp_dir, "a2_recv_data"])) ==
             File.read!("./test/fixtures/lotr.txt")

    :ok = File.close(a1_fd)
    :ok = File.close(a2_fd)

    a1_fd = File.open!(Path.join([tmp_dir, "a1_restart_recv_data"]), [:append])
    a2_fd = File.open!(Path.join([tmp_dir, "a2_restart_recv_data"]), [:append])

    a1_status = %{fd: a1_fd, completed: false, data_recv: false}
    a2_status = %{fd: a2_fd, completed: false, data_recv: false}

    :ok = ICEAgent.restart(agent1)
    {:ok, a1_ufrag, a1_pwd} = ICEAgent.get_local_credentials(agent1)
    :ok = ICEAgent.set_remote_credentials(agent2, a1_ufrag, a1_pwd)
    {:ok, a2_ufrag, a2_pwd} = ICEAgent.get_local_credentials(agent2)
    :ok = ICEAgent.set_remote_credentials(agent1, a2_ufrag, a2_pwd)

    :ok = ICEAgent.gather_candidates(agent1)
    :ok = ICEAgent.gather_candidates(agent2)

    assert p2p(agent1, agent2, a1_status, a2_status)

    assert File.read!(Path.join([tmp_dir, "a1_restart_recv_data"])) ==
             File.read!("./test/fixtures/lotr.txt")

    assert File.read!(Path.join([tmp_dir, "a2_restart_recv_data"])) ==
             File.read!("./test/fixtures/lotr.txt")
  end

  @tag :tmp_dir
  @tag :role_conflict
  test "P2P connection with role conflict", %{tmp_dir: tmp_dir} do
    stun_servers = ["stun:stun.l.google.com:19302"]
    # stun_servers = []

    ip_filter = fn
      {_, _, _, _, _, _, _, _} -> true
      {172, _, _, _} -> true
      _other -> true
    end

    {:ok, agent1} =
      ICEAgent.start_link(:controlled, ip_filter: ip_filter, stun_servers: stun_servers)

    {:ok, agent2} =
      ICEAgent.start_link(:controlled, ip_filter: ip_filter, stun_servers: stun_servers)

    {:ok, a1_ufrag, a1_pwd} = ICEAgent.get_local_credentials(agent1)
    {:ok, a2_ufrag, a2_pwd} = ICEAgent.get_local_credentials(agent2)

    :ok = ICEAgent.set_remote_credentials(agent2, a1_ufrag, a1_pwd)
    :ok = ICEAgent.set_remote_credentials(agent1, a2_ufrag, a2_pwd)

    :ok = ICEAgent.gather_candidates(agent1)
    :ok = ICEAgent.gather_candidates(agent2)

    a1_fd = File.open!(Path.join([tmp_dir, "a1_recv_data"]), [:append])
    a2_fd = File.open!(Path.join([tmp_dir, "a2_recv_data"]), [:append])

    a1_status = %{fd: a1_fd, completed: false, data_recv: false}
    a2_status = %{fd: a2_fd, completed: false, data_recv: false}

    assert p2p(agent1, agent2, a1_status, a2_status)

    assert File.read!(Path.join([tmp_dir, "a1_recv_data"])) ==
             File.read!("./test/fixtures/lotr.txt")

    assert File.read!(Path.join([tmp_dir, "a2_recv_data"])) ==
             File.read!("./test/fixtures/lotr.txt")
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

      {:ex_ice, ^agent1, :gathering_complete} ->
        ICEAgent.end_of_candidates(agent2)
        p2p(agent1, agent2, a1_status, a2_status)

      {:ex_ice, ^agent1, :connected} ->
        Logger.info("Connected, sending file...")

        Task.start(fn ->
          File.stream!("./test/fixtures/lotr.txt", [], 1000)
          |> Stream.each(fn chunk -> ICEAgent.send_data(agent1, chunk) end)
          |> Stream.run()

          ICEAgent.send_data(agent1, "eof")
        end)

        p2p(agent1, agent2, a1_status, a2_status)

      {:ex_ice, ^agent1, {:data, "eof"}} ->
        p2p(agent1, agent2, %{a1_status | data_recv: true}, a2_status)

      {:ex_ice, ^agent1, {:data, data}} ->
        :ok = IO.binwrite(a1_status.fd, data)
        p2p(agent1, agent2, a1_status, a2_status)

      {:ex_ice, ^agent1, :completed} ->
        Logger.info("Completed")
        a1_status = %{a1_status | completed: true}
        p2p(agent1, agent2, a1_status, a2_status)

      {:ex_ice, ^agent2, {:new_candidate, cand}} ->
        ICEAgent.add_remote_candidate(agent1, cand)
        p2p(agent1, agent2, a1_status, a2_status)

      {:ex_ice, ^agent2, :gathering_complete} ->
        ICEAgent.end_of_candidates(agent1)
        p2p(agent1, agent2, a1_status, a2_status)

      {:ex_ice, ^agent2, :completed} ->
        Logger.info("Completed")
        a2_status = %{a2_status | completed: true}
        p2p(agent1, agent2, a1_status, a2_status)

      {:ex_ice, ^agent2, :connected} ->
        Logger.info("Connected, sending file...")

        Task.start(fn ->
          File.stream!("./test/fixtures/lotr.txt", [], 1000)
          |> Stream.each(fn chunk -> ICEAgent.send_data(agent2, chunk) end)
          |> Stream.run()

          ICEAgent.send_data(agent2, "eof")
        end)

        p2p(agent1, agent2, a1_status, a2_status)

      {:ex_ice, ^agent2, {:data, "eof"}} ->
        p2p(agent1, agent2, a1_status, %{a2_status | data_recv: true})

      {:ex_ice, ^agent2, {:data, data}} ->
        :ok = IO.binwrite(a2_status.fd, data)
        p2p(agent1, agent2, a1_status, a2_status)
    after
      10_000 -> false
    end
  end
end
