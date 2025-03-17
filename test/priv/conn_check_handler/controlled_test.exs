defmodule ExICE.Priv.ConnCheckHandler.ControlledTest do
  use ExUnit.Case, async: true

  alias ExICE.Priv.ICEAgent
  alias ExICE.Priv.Attribute.{ICEControlled, ICEControlling, Priority, UseCandidate}
  alias ExICE.Priv.ConnCheckHandler.Controlled
  alias ExICE.Support.Transport

  alias ExSTUN.Message
  alias ExSTUN.Message.Type
  alias ExSTUN.Message.Attribute.Username

  defmodule IfDiscovery.Mock do
    @behaviour ExICE.Priv.IfDiscovery

    @impl true
    def getifaddrs() do
      ifs = [{~c"mockif", [{:flags, [:up, :running]}, {:addr, {192, 168, 0, 1}}]}]
      {:ok, ifs}
    end
  end

  @remote_cand ExICE.Candidate.new(:host, address: {192, 168, 0, 2}, port: 8445, priority: 123)
  @remote_cand2 ExICE.Candidate.new(:host, address: {192, 168, 0, 3}, port: 8445, priority: 122)

  describe "incoming binding request" do
    setup do
      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlled,
          transport_module: Transport.Mock,
          if_discovery_module: IfDiscovery.Mock
        )
        |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
        |> ICEAgent.gather_candidates()

      req =
        binding_request(
          ice_agent.role,
          ice_agent.tiebreaker,
          "somepwd",
          ice_agent.local_ufrag,
          ice_agent.local_pwd
        )

      use_c_req =
        binding_request(
          ice_agent.role,
          ice_agent.tiebreaker,
          "somepwd",
          ice_agent.local_ufrag,
          ice_agent.local_pwd,
          true
        )

      %{ice_agent: ice_agent, req: req, use_c_req: use_c_req}
    end

    test "on failed pair in failed state", %{ice_agent: ice_agent, req: req, use_c_req: use_c_req} do
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, @remote_cand)

      # set pair and agent states to failed
      [pair_id] = Map.keys(ice_agent.checklist)
      ice_agent = put_in(ice_agent.checklist[pair_id].state, :failed)
      ice_agent = %{ice_agent | state: :failed}

      # try to handle binding request
      [socket] = ice_agent.sockets
      pair = Map.fetch!(ice_agent.checklist, pair_id)
      new_ice_agent = Controlled.handle_conn_check_request(ice_agent, pair, req, nil)

      # assert a response has not been sent, and pair and agent are still in state failed
      new_pair = Map.fetch!(new_ice_agent.checklist, pair_id)
      assert Transport.Mock.recv(socket) == nil
      assert new_ice_agent.state == :failed
      assert new_pair.state == :failed
      assert new_pair.requests_received == pair.requests_received + 1
      assert new_pair.responses_sent == pair.responses_sent

      # the same when with UseCandidate flag
      new_ice_agent =
        Controlled.handle_conn_check_request(ice_agent, pair, use_c_req, %UseCandidate{})

      # assert a response has not been sent, and pair and agent are still in state failed
      new_pair = Map.fetch!(new_ice_agent.checklist, pair_id)
      assert Transport.Mock.recv(socket) == nil
      assert new_ice_agent.state == :failed
      assert new_pair.state == :failed
      assert new_pair.requests_received == pair.requests_received + 1
      assert new_pair.responses_sent == pair.responses_sent
    end

    test "on failed pair in completed state", %{
      ice_agent: ice_agent,
      req: req,
      use_c_req: use_c_req
    } do
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, @remote_cand)
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, @remote_cand2)

      # set pair and agent states
      [pair_id1, pair_id2] = Map.keys(ice_agent.checklist)
      ice_agent = put_in(ice_agent.checklist[pair_id1].state, :failed)
      ice_agent = put_in(ice_agent.checklist[pair_id2].state, :succeeded)
      ice_agent = put_in(ice_agent.checklist[pair_id2].valid?, true)
      ice_agent = put_in(ice_agent.selected_pair_id, pair_id2)
      ice_agent = %{ice_agent | state: :completed}

      # try to handle binding request
      [socket] = ice_agent.sockets
      pair1 = Map.fetch!(ice_agent.checklist, pair_id1)
      new_ice_agent = Controlled.handle_conn_check_request(ice_agent, pair1, req, nil)

      # assert a response has not been sent, pair_id1 is still in state failed and agent is still in state completed
      new_pair1 = Map.fetch!(new_ice_agent.checklist, pair_id1)
      assert Transport.Mock.recv(socket) == nil
      assert new_ice_agent.state == :completed
      assert new_pair1.state == :failed
      assert new_pair1.requests_received == pair1.requests_received + 1
      assert new_pair1.responses_sent == pair1.responses_sent

      # the same when with UseCandidate flag
      new_ice_agent =
        Controlled.handle_conn_check_request(ice_agent, pair1, use_c_req, %UseCandidate{})

      # assert a response has not been sent, pair_id1 is still in state failed and agent is still in state completed
      new_pair1 = Map.fetch!(new_ice_agent.checklist, pair_id1)
      assert Transport.Mock.recv(socket) == nil
      assert new_ice_agent.state == :completed
      assert new_pair1.state == :failed
      assert new_pair1.requests_received == pair1.requests_received + 1
      assert new_pair1.responses_sent == pair1.responses_sent
    end

    test "on failed pair in connected state", %{
      ice_agent: ice_agent,
      req: req,
      use_c_req: use_c_req
    } do
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, @remote_cand)
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, @remote_cand2)

      # set pair and agent states
      [pair_id1, pair_id2] = Map.keys(ice_agent.checklist)
      ice_agent = put_in(ice_agent.checklist[pair_id1].state, :failed)
      ice_agent = put_in(ice_agent.checklist[pair_id2].state, :succeeded)
      ice_agent = put_in(ice_agent.checklist[pair_id2].valid?, true)
      ice_agent = %{ice_agent | state: :connected}

      # try to handle binding request
      [socket] = ice_agent.sockets
      pair1 = Map.fetch!(ice_agent.checklist, pair_id1)
      new_ice_agent = Controlled.handle_conn_check_request(ice_agent, pair1, req, nil)

      # assert a response has been sent, pair_id1 is waiting and agent is connected
      new_pair1 = Map.fetch!(new_ice_agent.checklist, pair_id1)
      assert Transport.Mock.recv(socket) != nil
      assert new_ice_agent.state == :connected
      assert new_pair1.state == :waiting
      assert new_pair1.nominate? == false
      assert new_pair1.requests_received == pair1.requests_received + 1
      assert new_pair1.responses_sent == pair1.responses_sent + 1

      # the same when with UseCandidate flag
      new_ice_agent =
        Controlled.handle_conn_check_request(ice_agent, pair1, use_c_req, %UseCandidate{})

      # assert a response has been sent, pair is waiting and agent is connected
      new_pair1 = Map.fetch!(new_ice_agent.checklist, pair_id1)
      assert Transport.Mock.recv(socket) != nil
      assert new_ice_agent.state == :connected
      assert new_pair1.state == :waiting
      assert new_pair1.nominate? == true
      assert new_pair1.requests_received == pair1.requests_received + 1
      assert new_pair1.responses_sent == pair1.responses_sent + 1
    end

    test "on selected pair in completed state", %{
      ice_agent: ice_agent,
      req: req,
      use_c_req: use_c_req
    } do
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, @remote_cand)

      # set pair and agent states
      [pair_id1] = Map.keys(ice_agent.checklist)
      ice_agent = put_in(ice_agent.checklist[pair_id1].state, :succeeded)
      ice_agent = put_in(ice_agent.checklist[pair_id1].valid?, true)
      # That's a little hack as we are mocking a lot of things.
      # To avoid it, we would have to go through the full req/resp flow using handle_udp function.
      ice_agent = put_in(ice_agent.checklist[pair_id1].discovered_pair_id, pair_id1)

      ice_agent = put_in(ice_agent.selected_pair_id, pair_id1)
      ice_agent = %{ice_agent | state: :completed}

      # try to handle binding request
      [socket] = ice_agent.sockets
      pair1 = Map.fetch!(ice_agent.checklist, pair_id1)
      new_ice_agent = Controlled.handle_conn_check_request(ice_agent, pair1, req, nil)

      # assert a response has been sent, pair_id1 is still in state succeeded and agent is still in state completed
      new_pair1 = Map.fetch!(new_ice_agent.checklist, pair_id1)
      assert Transport.Mock.recv(socket) != nil
      assert new_ice_agent.state == :completed
      assert new_ice_agent.selected_pair_id == pair_id1
      assert new_pair1.state == :succeeded
      assert new_pair1.valid? == true
      assert new_pair1.requests_received == pair1.requests_received + 1
      assert new_pair1.responses_sent == pair1.responses_sent + 1

      # the same when with UseCandidate flag
      new_ice_agent =
        Controlled.handle_conn_check_request(ice_agent, pair1, use_c_req, %UseCandidate{})

      # assert a response has not been sent, pair_id1 is still in state failed and agent is still in state completed
      new_pair1 = Map.fetch!(new_ice_agent.checklist, pair_id1)
      assert Transport.Mock.recv(socket) != nil
      assert new_ice_agent.state == :completed
      assert new_ice_agent.selected_pair_id == pair_id1
      assert new_pair1.state == :succeeded
      assert new_pair1.valid? == true
      assert new_pair1.requests_received == pair1.requests_received + 1
      assert new_pair1.responses_sent == pair1.responses_sent + 1
    end

    test "on succeeded pair in connected state", %{
      ice_agent: ice_agent,
      req: req,
      use_c_req: use_c_req
    } do
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, @remote_cand)

      # set pair and agent states
      [pair_id1] = Map.keys(ice_agent.checklist)
      ice_agent = put_in(ice_agent.checklist[pair_id1].state, :succeeded)
      ice_agent = put_in(ice_agent.checklist[pair_id1].valid?, true)
      # That's a little hack as we are mocking a lot of things.
      # To avoid it, we would have to go through the full req/resp flow using handle_udp function.
      ice_agent = put_in(ice_agent.checklist[pair_id1].discovered_pair_id, pair_id1)
      ice_agent = %{ice_agent | state: :connected}

      # try to handle binding request
      [socket] = ice_agent.sockets
      pair1 = Map.fetch!(ice_agent.checklist, pair_id1)
      new_ice_agent = Controlled.handle_conn_check_request(ice_agent, pair1, req, nil)

      # assert a response has been sent, pair_id1 is still in state succeeded and agent is still in state connected
      new_pair1 = Map.fetch!(new_ice_agent.checklist, pair_id1)
      assert Transport.Mock.recv(socket) != nil
      assert new_ice_agent.state == :connected
      assert new_ice_agent.selected_pair_id == nil
      assert new_pair1.state == :succeeded
      assert new_pair1.valid? == true
      assert new_pair1.requests_received == pair1.requests_received + 1
      assert new_pair1.responses_sent == pair1.responses_sent + 1

      # the same when with UseCandidate flag
      new_ice_agent =
        Controlled.handle_conn_check_request(ice_agent, pair1, use_c_req, %UseCandidate{})

      # assert a response has been sent, pair_id1 is still in state succeeded, agent is still in state connected but there is also selected pair
      new_pair1 = Map.fetch!(new_ice_agent.checklist, pair_id1)
      assert Transport.Mock.recv(socket) != nil
      assert new_ice_agent.state == :connected
      assert new_ice_agent.selected_pair_id == pair_id1
      assert new_pair1.state == :succeeded
      assert new_pair1.valid? == true
      assert new_pair1.requests_received == pair1.requests_received + 1
      assert new_pair1.responses_sent == pair1.responses_sent + 1
    end

    test "on succeeded pair that has higher prio in connected state", %{
      ice_agent: ice_agent,
      use_c_req: use_c_req
    } do
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, @remote_cand)
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, @remote_cand2)

      # set pair and agent states
      [pair_id1, pair_id2] = Map.keys(ice_agent.checklist)
      pair2 = Map.fetch!(ice_agent.checklist, pair_id2)
      ice_agent = put_in(ice_agent.checklist[pair_id1].state, :succeeded)
      ice_agent = put_in(ice_agent.checklist[pair_id1].priority, pair2.priority + 1)
      ice_agent = put_in(ice_agent.checklist[pair_id1].valid?, true)
      ice_agent = put_in(ice_agent.checklist[pair_id1].discovered_pair_id, pair_id1)
      ice_agent = put_in(ice_agent.checklist[pair_id2].state, :succeeded)
      ice_agent = put_in(ice_agent.checklist[pair_id2].valid?, true)
      ice_agent = put_in(ice_agent.checklist[pair_id2].discovered_pair_id, pair_id2)
      ice_agent = put_in(ice_agent.selected_pair_id, pair_id2)
      ice_agent = %{ice_agent | state: :connected}

      # try to handle binding request
      [socket] = ice_agent.sockets
      pair1 = Map.fetch!(ice_agent.checklist, pair_id1)

      new_ice_agent =
        Controlled.handle_conn_check_request(ice_agent, pair1, use_c_req, %UseCandidate{})

      # assert a response has been sent, and pair_id1 is a new selected pair
      new_pair1 = Map.fetch!(new_ice_agent.checklist, pair_id1)
      assert Transport.Mock.recv(socket) != nil
      assert new_ice_agent.state == :connected
      assert new_ice_agent.selected_pair_id == pair_id1
      assert new_pair1.state == :succeeded
      assert new_pair1.valid? == true
      assert new_pair1.requests_received == pair1.requests_received + 1
      assert new_pair1.responses_sent == pair1.responses_sent + 1
    end

    test "on unknown pair in connected state", %{
      ice_agent: ice_agent,
      req: req,
      use_c_req: use_c_req
    } do
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, @remote_cand)
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, @remote_cand2)

      # set pair and agent states
      [pair_id1, pair_id2] = Map.keys(ice_agent.checklist)
      ice_agent = put_in(ice_agent.checklist[pair_id1].state, :succeeded)
      ice_agent = put_in(ice_agent.checklist[pair_id1].valid?, true)
      ice_agent = put_in(ice_agent.checklist[pair_id1].discovered_pair_id, pair_id1)
      ice_agent = %{ice_agent | state: :connected}

      # Pop pair2 so it's not in the checklist but its remote candidate is already in ice state
      # that's a little hack as we omit handle_udp, which is responsible for adding prflx candidate to the state.
      # In other case, we wouldn't be able to send success response.
      {pair2, ice_agent} = pop_in(ice_agent.checklist[pair_id2])

      # try to handle binding request from unknown pair
      [socket] = ice_agent.sockets
      new_ice_agent = Controlled.handle_conn_check_request(ice_agent, pair2, req, nil)

      # assert a response has been sent, and we have a new pair in the checklist
      new_pair2 = Map.fetch!(new_ice_agent.checklist, pair_id2)
      assert Transport.Mock.recv(socket) != nil
      assert new_ice_agent.state == :connected
      assert new_pair2.state == :waiting
      assert new_pair2.valid? == false
      assert new_pair2.nominate? == false
      assert new_pair2.requests_received == pair2.requests_received + 1
      assert new_pair2.responses_sent == pair2.responses_sent + 1

      # the same with UseCandidate flag
      new_ice_agent =
        Controlled.handle_conn_check_request(ice_agent, pair2, use_c_req, %UseCandidate{})

      # assert a response has been sent, and we have a new pair in the checklist
      new_pair2 = Map.fetch!(new_ice_agent.checklist, pair_id2)
      assert Transport.Mock.recv(socket) != nil
      assert new_ice_agent.state == :connected
      assert new_pair2.state == :waiting
      assert new_pair2.valid? == false
      assert new_pair2.nominate? == true
      assert new_pair2.requests_received == pair2.requests_received + 1
      assert new_pair2.responses_sent == pair2.responses_sent + 1
    end

    defp binding_request(
           role,
           tiebreaker,
           local_ufrag,
           remote_ufrag,
           remote_pwd,
           use_candidate \\ false
         ) do
      ice_attrs =
        cond do
          role == :controlled and use_candidate == true ->
            [%ICEControlling{tiebreaker: tiebreaker + 1}, %UseCandidate{}]

          role == :controlled and use_candidate == false ->
            [%ICEControlling{tiebreaker: tiebreaker + 1}]

          role == :controlling ->
            [%ICEControlled{tiebreaker: tiebreaker - 1}]
        end

      attrs =
        [
          %Username{value: "#{remote_ufrag}:#{local_ufrag}"},
          %Priority{priority: 1234}
        ] ++ ice_attrs

      Message.new(%Type{class: :request, method: :binding}, attrs)
      |> Message.with_integrity(remote_pwd)
      |> Message.with_fingerprint()
    end
  end
end
