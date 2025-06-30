defmodule ExICE.Priv.ICEAgentTest do
  use ExUnit.Case, async: true

  alias ExICE.Priv.{Candidate, CandidatePair, IfDiscovery, ICEAgent}
  alias ExICE.Priv.Attribute.{ICEControlled, ICEControlling, Priority, UseCandidate}
  alias ExICE.Support.Transport

  alias ExSTUN.Message
  alias ExSTUN.Message.Type
  alias ExSTUN.Message.Attribute.{ErrorCode, Nonce, Realm, Username, XORMappedAddress}

  alias ExTURN.Attribute.{Data, Lifetime, XORRelayedAddress, XORPeerAddress}

  defmodule IfDiscovery.Mock do
    @behaviour ExICE.Priv.IfDiscovery

    @impl true
    def getifaddrs() do
      ifs = [{~c"mockif", [{:flags, [:up, :running]}, {:addr, {192, 168, 0, 1}}]}]
      {:ok, ifs}
    end
  end

  defmodule IfDiscovery.IPV6.Mock do
    @behaviour ExICE.Priv.IfDiscovery

    @impl true
    def getifaddrs() do
      ifs = [{~c"mockif", [{:flags, [:up, :running]}, {:addr, {64_512, 0, 0, 0, 0, 0, 0, 1}}]}]
      {:ok, ifs}
    end
  end

  defmodule Candidate.Mock do
    @moduledoc false
    @behaviour ExICE.Priv.Candidate

    alias ExICE.Priv.CandidateBase

    @type t() :: %__MODULE__{base: CandidateBase.t()}

    @enforce_keys [:base]
    defstruct @enforce_keys

    @impl true
    def new(config) do
      %__MODULE__{base: CandidateBase.new(:host, config)}
    end

    @impl true
    def marshal(cand), do: CandidateBase.marshal(cand.base)

    @impl true
    def family(cand), do: CandidateBase.family(cand.base)

    @impl true
    def to_candidate(cand), do: CandidateBase.to_candidate(cand.base)

    @impl true
    def send_data(cand, _dst_ip, _dst_port, _data) do
      {:error, :invalid_data, cand}
    end
  end

  @remote_cand ExICE.Candidate.new(:host, address: {192, 168, 0, 2}, port: 8445, priority: 123)
  @remote_cand2 ExICE.Candidate.new(:host, address: {192, 168, 0, 3}, port: 8445, priority: 122)

  describe "unmarshal_remote_candidate/1" do
    test "with correct candidate" do
      cand = "1 1 UDP 1686052863 127.0.0.1 57940 typ srflx raddr 0.0.0.0 rport 0"
      assert {:ok, %ExICE.Candidate{}} = ICEAgent.unmarshal_remote_candidate(cand)
    end

    test "with invalid candidate" do
      assert {:error, _reason} = ICEAgent.unmarshal_remote_candidate("some invalid cand string")
    end

    test "with invalid address" do
      cand = "1 1 UDP 1686052863 someincalidmdnsadddress 57940 typ srflx raddr 0.0.0.0 rport 0"
      assert {:error, _reason} = ICEAgent.unmarshal_remote_candidate(cand)
    end

    test "with MDNS resolver not started" do
      # this test checks what happens when MDNS resolver has not been started due to too old Erlang version

      # stop MDNS resolver
      pid = Process.whereis(ExICE.Priv.MDNS.Resolver)
      assert :ok == GenServer.stop(pid)
      assert nil == Process.whereis(ExICE.Priv.MDNS.Resolver)

      # try to resolve some address
      cand = "1 1 UDP 1686052863 example.local 57940 typ srflx raddr 0.0.0.0 rport 0"

      assert {:error, {:resolve_address, :mdns_resolver_not_alive}} =
               ICEAgent.unmarshal_remote_candidate(cand)
    end
  end

  describe "add_remote_candidate/2" do
    setup do
      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlling,
          if_discovery_module: IfDiscovery.Mock,
          transport_module: Transport.Mock
        )
        |> ICEAgent.set_remote_credentials("remoteufrag", "remotepwd")
        |> ICEAgent.gather_candidates()

      %{ice_agent: ice_agent}
    end

    test "with correct remote candidate", %{ice_agent: ice_agent} do
      # assert there are no remote candidates and no pairs
      assert %{} == ice_agent.remote_cands
      assert %{} == ice_agent.checklist

      ice_agent = ICEAgent.add_remote_candidate(ice_agent, @remote_cand)

      assert [%ExICE.Candidate{} = r_cand] = Map.values(ice_agent.remote_cands)
      # override id for the purpose of comparison
      r_cand = %ExICE.Candidate{r_cand | id: @remote_cand.id}
      assert r_cand == @remote_cand

      # assert that a new pair has been created
      assert [%CandidatePair{} = cand_pair] = Map.values(ice_agent.checklist)
      assert cand_pair.remote_cand_id == r_cand.id
    end

    test "with duplicated prflx candidate", %{ice_agent: ice_agent} do
      # Try to add a remote host candidate that has already been discovered as prflx candidate.
      # This should result in updating candidate's type and priority and pair's priority.
      # Also, selected_pair_id should change.
      assert %{} == ice_agent.remote_cands
      assert %{} == ice_agent.checklist

      # prepare candiadtes
      remote_cand1 =
        ExICE.Candidate.new(:host, address: {192, 168, 0, 2}, port: 8445, priority: 123)

      remote_cand2 =
        ExICE.Candidate.new(:host, address: {192, 168, 0, 3}, port: 8445, priority: 122)

      [socket] = ice_agent.sockets

      # discover prflx candidate
      req =
        binding_request(
          ice_agent.role,
          ice_agent.tiebreaker,
          ice_agent.remote_ufrag,
          ice_agent.local_ufrag,
          ice_agent.local_pwd,
          priority: 120
        )

      ice_agent =
        ICEAgent.handle_udp(ice_agent, socket, remote_cand1.address, remote_cand1.port, req)

      assert [prflx_cand] = Map.values(ice_agent.remote_cands)
      assert [prflx_pair] = Map.values(ice_agent.checklist)
      assert prflx_cand.type == :prflx
      prflx_pair = %CandidatePair{prflx_pair | state: :succeeded, valid?: true}
      ice_agent = put_in(ice_agent.checklist[prflx_pair.id], prflx_pair)

      # add another remote candidate that will result in higher pair priority
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, remote_cand2)

      host_pair =
        Enum.find(Map.values(ice_agent.checklist), fn pair ->
          pair.remote_cand_id == remote_cand2.id
        end)

      assert host_pair.priority > prflx_pair.priority
      host_pair = %CandidatePair{host_pair | state: :succeeded, valid?: true}
      ice_agent = put_in(ice_agent.checklist[host_pair.id], host_pair)
      ice_agent = %ICEAgent{ice_agent | selected_pair_id: host_pair.id}

      # try to add host candidate that is the same as prflx candidate
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, remote_cand1)

      host_pair2 =
        Enum.find(Map.values(ice_agent.checklist), fn pair ->
          pair.remote_cand_id == prflx_cand.id
        end)

      # assert that prflx candidate change its type and priority, and the relevant pair
      # also changed its priority and became a new selected pair
      host_cand =
        Enum.find(Map.values(ice_agent.remote_cands), fn cand ->
          cand.id == prflx_cand.id
        end)

      assert host_cand.type == :host
      assert host_cand.priority > prflx_cand.priority
      assert host_pair2.priority > prflx_pair.priority
      assert host_pair2.priority > host_pair.priority
      assert ice_agent.selected_pair_id == host_pair2.id
    end

    test "with duplicated remote candidate", %{ice_agent: ice_agent} do
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, @remote_cand)
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, @remote_cand)

      # assert there is only one remote candidate and one pair
      assert [%ExICE.Candidate{}] = Map.values(ice_agent.remote_cands)
      assert [%CandidatePair{}] = Map.values(ice_agent.checklist)
    end

    test "without remote credentials", %{ice_agent: ice_agent} do
      ice_agent = %{ice_agent | remote_ufrag: nil, remote_pwd: nil}
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, @remote_cand)
      assert %{} == ice_agent.remote_cands
    end

    test "without role", %{ice_agent: ice_agent} do
      ice_agent = %{ice_agent | role: nil}
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, @remote_cand)
      assert %{} == ice_agent.remote_cands
    end

    test "after setting end-of-candidates", %{ice_agent: ice_agent} do
      ice_agent = ICEAgent.end_of_candidates(ice_agent)
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, @remote_cand)
      assert %{} == ice_agent.remote_cands
    end
  end

  test "set_role/2" do
    ice_agent =
      ICEAgent.new(
        controlling_process: self(),
        role: nil,
        if_discovery_module: IfDiscovery.Mock,
        transport_module: Transport.Mock
      )
      |> ICEAgent.set_remote_credentials("remoteufrag", "remotepwd")

    ice_agent = ICEAgent.set_role(ice_agent, :controlling)
    assert ice_agent.role == :controlling

    # role shouldn't change as we don't allow for changing the role once it has been initialized
    ice_agent = ICEAgent.set_role(ice_agent, :controlled)
    assert ice_agent.role == :controlling

    # assert that timer has not been fired as there is no work to do
    refute_receive :ta_timeout
  end

  describe "gather_candidates/1" do
    setup do
      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlling,
          if_discovery_module: IfDiscovery.Mock,
          transport_module: Transport.Mock
        )
        |> ICEAgent.set_remote_credentials("remoteufrag", "remotepwd")

      %{ice_agent: ice_agent}
    end

    test "when there already are remote candidates", %{ice_agent: ice_agent} do
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, @remote_cand)

      # assert that there are no pairs and no local cands
      assert [] == Map.values(ice_agent.checklist)
      assert [] == Map.values(ice_agent.local_cands)

      # gather candidates
      ice_agent = ICEAgent.gather_candidates(ice_agent)
      [host_cand] = Map.values(ice_agent.local_cands)

      # assert that a new pair has been created
      assert [%CandidatePair{} = cand_pair] = Map.values(ice_agent.checklist)
      assert cand_pair.local_cand_id == host_cand.base.id
    end

    test "without role", %{ice_agent: ice_agent} do
      ice_agent = %{ice_agent | role: nil}
      ice_agent = ICEAgent.gather_candidates(ice_agent)
      assert %{} == ice_agent.local_cands
    end
  end

  test "handle_udp/5" do
    ice_agent =
      ICEAgent.new(
        controlling_process: self(),
        role: :controlling,
        if_discovery_module: IfDiscovery.Mock,
        transport_module: Transport.Mock
      )
      |> ICEAgent.set_remote_credentials("remoteufrag", "remotepwd")
      |> ICEAgent.gather_candidates()
      |> ICEAgent.add_remote_candidate(@remote_cand)

    # mark candidate/pair as closed/failed
    [cand] = Map.values(ice_agent.local_cands)
    cand = put_in(cand.base.closed?, true)
    ice_agent = put_in(ice_agent.local_cands[cand.base.id], cand)

    [pair] = Map.values(ice_agent.checklist)
    pair = %{pair | state: :failed}
    ice_agent = put_in(ice_agent.checklist[pair.id], pair)

    # try to feed data on closed candidate, it should be ignored
    [socket] = ice_agent.sockets
    # make sure agent is not in the state failed before feeding data
    assert ice_agent.state != :failed

    # stun message
    req =
      binding_request(
        ice_agent.role,
        ice_agent.tiebreaker,
        "remoteufrag",
        ice_agent.local_ufrag,
        ice_agent.local_pwd
      )

    new_ice_agent =
      ICEAgent.handle_udp(
        ice_agent,
        socket,
        @remote_cand.address,
        @remote_cand.port,
        req
      )

    assert new_ice_agent == ice_agent

    # custom data
    new_ice_agent =
      ICEAgent.handle_udp(
        ice_agent,
        socket,
        @remote_cand.address,
        @remote_cand.port,
        "some binary"
      )

    assert new_ice_agent == ice_agent
  end

  test "close/1" do
    ice_agent =
      ICEAgent.new(
        controlling_process: self(),
        role: :controlling,
        if_discovery_module: IfDiscovery.Mock,
        transport_module: Transport.Mock
      )
      |> ICEAgent.set_remote_credentials("remoteufrag", "remotepwd")
      |> ICEAgent.gather_candidates()
      |> ICEAgent.add_remote_candidate(@remote_cand)

    assert_receive {:ex_ice, _pid, {:gathering_state_change, :complete}}

    ice_agent = ICEAgent.close(ice_agent)

    assert ice_agent.state == :closed
    assert ice_agent.gathering_state == :complete
    assert [%{state: :failed} = pair] = Map.values(ice_agent.checklist)
    assert [%{base: %{closed?: true}}] = Map.values(ice_agent.local_cands)
    # make sure that sockets and remote cands were not cleared
    assert [_remote_cand] = Map.values(ice_agent.remote_cands)
    assert [socket] = ice_agent.sockets

    # check stats
    stats = ICEAgent.get_stats(ice_agent)
    assert stats.local_candidates != %{}
    assert stats.remote_candidates != %{}
    assert stats.candidate_pairs != %{}
    assert stats.state == :closed

    refute_received {:ex_ice, _pid, {:connection_state_change, :closed}}
    refute_received {:ex_ice, _pid, {:gathering_state_change, :complete}}

    # assert these functions are ignored
    assert ice_agent == ICEAgent.set_role(ice_agent, :controlled)
    assert ice_agent == ICEAgent.set_remote_credentials(ice_agent, "remoteufrag2", "remotepwd2")
    assert ice_agent == ICEAgent.gather_candidates(ice_agent)
    assert ice_agent == ICEAgent.add_remote_candidate(ice_agent, @remote_cand2)
    assert ice_agent == ICEAgent.end_of_candidates(ice_agent)
    assert ice_agent == ICEAgent.send_data(ice_agent, <<0, 1, 2>>)
    assert ice_agent == ICEAgent.restart(ice_agent)
    assert ice_agent == ICEAgent.handle_ta_timeout(ice_agent)
    # only eoc_timer should change to nil
    assert %{ice_agent | eoc_timer: nil} == ICEAgent.handle_eoc_timeout(ice_agent)
    assert ice_agent == ICEAgent.handle_pair_timeout(ice_agent)
    assert ice_agent == ICEAgent.handle_keepalive_timeout(ice_agent, pair.id)

    assert ice_agent ==
             ICEAgent.handle_udp(
               ice_agent,
               socket,
               @remote_cand.address,
               @remote_cand.port,
               "some data"
             )
  end

  test "doesn't add pairs with srflx local candidate to the checklist" do
    ice_agent =
      ICEAgent.new(
        controlling_process: self(),
        role: :controlling,
        transport_module: Transport.Mock,
        if_discovery_module: IfDiscovery.Mock
      )
      |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
      |> ICEAgent.gather_candidates()

    [socket] = ice_agent.sockets
    [host_cand] = Map.values(ice_agent.local_cands)

    srflx_cand =
      ExICE.Priv.Candidate.Srflx.new(
        address: {192, 168, 0, 2},
        port: 1234,
        base_address: host_cand.base.base_address,
        base_port: host_cand.base.base_port,
        priority: host_cand.base.priority - 1,
        transport_module: ice_agent.transport_module,
        socket: socket
      )

    local_cands = %{host_cand.base.id => host_cand, srflx_cand.base.id => srflx_cand}
    ice_agent = %{ice_agent | local_cands: local_cands}

    ice_agent = ICEAgent.add_remote_candidate(ice_agent, @remote_cand)

    # assert there is only one pair with host local candidate
    assert [pair] = Map.values(ice_agent.checklist)
    assert pair.local_cand_id == host_cand.base.id
  end

  test "forwards data received on a faild pair and re-schedules" do
    ice_agent =
      ICEAgent.new(
        controlling_process: self(),
        role: :controlling,
        transport_module: Transport.Mock,
        if_discovery_module: IfDiscovery.Mock
      )
      |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
      |> ICEAgent.gather_candidates()
      |> ICEAgent.add_remote_candidate(@remote_cand)

    [socket] = ice_agent.sockets

    # mark pair as failed
    [pair] = Map.values(ice_agent.checklist)
    ice_agent = put_in(ice_agent.checklist[pair.id], %{pair | state: :failed})

    # clear ta_timer, ignore outgoing binding request that has been generated
    ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
    assert ice_agent.ta_timer == nil

    # feed some data
    ice_agent =
      ICEAgent.handle_udp(ice_agent, socket, @remote_cand.address, @remote_cand.port, "some data")

    # assert that data has been passed
    assert_receive {:ex_ice, _pid, {:data, "some data"}}

    # assert that pair is re-scheduled
    assert [pair] = Map.values(ice_agent.checklist)
    assert pair.state == :waiting
    assert ice_agent.ta_timer != nil
  end

  describe "re-schedules failed pair on incoming binding request" do
    test "with controlling ice agent" do
      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlling,
          transport_module: Transport.Mock,
          if_discovery_module: IfDiscovery.Mock
        )
        |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
        |> ICEAgent.gather_candidates()
        |> ICEAgent.add_remote_candidate(@remote_cand)

      test_rescheduling(ice_agent, @remote_cand)
    end

    test "with controlled ice agent" do
      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlled,
          transport_module: Transport.Mock,
          if_discovery_module: IfDiscovery.Mock
        )
        |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
        |> ICEAgent.gather_candidates()
        |> ICEAgent.add_remote_candidate(@remote_cand)

      test_rescheduling(ice_agent, @remote_cand)
    end

    defp test_rescheduling(ice_agent, remote_cand) do
      [socket] = ice_agent.sockets

      # make sure we won't overflow when modifying tiebreakers later on
      ice_agent = %{ice_agent | tiebreaker: 100}

      # mark pair as failed
      [pair] = Map.values(ice_agent.checklist)
      ice_agent = put_in(ice_agent.checklist[pair.id], %{pair | state: :failed})

      # clear ta_timer, ignore outgoing binding request that has been generated
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
      assert ice_agent.ta_timer == nil

      # feed incoming binding request
      ice_attrs =
        if ice_agent.role == :controlled do
          [%ICEControlling{tiebreaker: ice_agent.tiebreaker + 1}, %UseCandidate{}]
        else
          [%ICEControlled{tiebreaker: ice_agent.tiebreaker - 1}]
        end

      attrs =
        [
          %Username{value: "#{ice_agent.local_ufrag}:someufrag"},
          %Priority{priority: 1234}
        ] ++ ice_attrs

      request =
        Message.new(%Type{class: :request, method: :binding}, attrs)
        |> Message.with_integrity(ice_agent.local_pwd)
        |> Message.with_fingerprint()

      raw_request = Message.encode(request)

      ice_agent =
        ICEAgent.handle_udp(ice_agent, socket, remote_cand.address, remote_cand.port, raw_request)

      # assert that pair is re-scheduled
      assert [pair] = Map.values(ice_agent.checklist)
      assert pair.state == :waiting
      assert ice_agent.ta_timer != nil
    end
  end

  describe "keepalive" do
    setup do
      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlling,
          if_discovery_module: IfDiscovery.Mock,
          transport_module: Transport.Mock
        )
        |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
        |> ICEAgent.gather_candidates()
        |> ICEAgent.add_remote_candidate(@remote_cand)

      %{ice_agent: ice_agent}
    end

    test "timeout on connected pair", %{ice_agent: ice_agent} do
      ice_agent = connect(ice_agent)

      [socket] = ice_agent.sockets
      [pair] = Map.values(ice_agent.checklist)
      ice_agent = ICEAgent.handle_keepalive_timeout(ice_agent, pair.id)

      assert packet = Transport.Mock.recv(socket)
      assert {:ok, msg} = ExSTUN.Message.decode(packet)
      assert msg.type == %ExSTUN.Message.Type{class: :request, method: :binding}

      # assert there are required attributes
      username = "#{ice_agent.remote_ufrag}:#{ice_agent.local_ufrag}"
      assert length(msg.attributes) == 5

      assert {:ok, %Username{value: ^username}} = ExSTUN.Message.get_attribute(msg, Username)
      assert {:ok, %ICEControlling{}} = ExSTUN.Message.get_attribute(msg, ICEControlling)
      assert {:ok, %Priority{}} = ExSTUN.Message.get_attribute(msg, Priority)

      # authenticate and check fingerprint
      assert :ok == ExSTUN.Message.check_fingerprint(msg)
      assert :ok == ExSTUN.Message.authenticate(msg, ice_agent.remote_pwd)

      # check stats
      new_pair = Map.fetch!(ice_agent.checklist, pair.id)
      assert new_pair.requests_sent == pair.requests_sent + 1
      assert new_pair.responses_received == pair.responses_received
    end

    test "timeout on unconnected pair", %{ice_agent: ice_agent} do
      [socket] = ice_agent.sockets
      [pair] = Map.values(ice_agent.checklist)
      ICEAgent.handle_keepalive_timeout(ice_agent, pair.id)

      assert nil == Transport.Mock.recv(socket)

      # check stats
      new_pair = Map.fetch!(ice_agent.checklist, pair.id)
      assert new_pair.requests_sent == pair.requests_sent
      assert new_pair.responses_received == pair.responses_received
    end

    test "success response", %{ice_agent: ice_agent} do
      ice_agent = connect(ice_agent)

      [socket] = ice_agent.sockets
      [remote_cand] = Map.values(ice_agent.remote_cands)
      [pair] = Map.values(ice_agent.checklist)

      # trigger keepalive request
      ice_agent = ICEAgent.handle_keepalive_timeout(ice_agent, pair.id)
      assert packet = Transport.Mock.recv(socket)
      assert {:ok, req} = ExSTUN.Message.decode(packet)

      # create a response
      resp =
        binding_response(
          req.transaction_id,
          ice_agent.transport_module,
          socket,
          ice_agent.remote_pwd
        )

      # wait so that we can observe a change in last_seen later on
      Process.sleep(1)

      ice_agent =
        ICEAgent.handle_udp(ice_agent, socket, remote_cand.address, remote_cand.port, resp)

      [new_pair] = Map.values(ice_agent.checklist)
      assert new_pair.last_seen > pair.last_seen
      assert new_pair.responses_received == pair.responses_received + 1
    end

    test "invalid success response", %{ice_agent: ice_agent} do
      ice_agent = connect(ice_agent)

      [socket] = ice_agent.sockets
      [remote_cand] = Map.values(ice_agent.remote_cands)
      [pair] = Map.values(ice_agent.checklist)

      # trigger keepalive request
      ice_agent = ICEAgent.handle_keepalive_timeout(ice_agent, pair.id)
      assert packet = Transport.Mock.recv(socket)
      assert {:ok, req} = ExSTUN.Message.decode(packet)

      # create a response using wrong password
      resp =
        binding_response(
          req.transaction_id,
          ice_agent.transport_module,
          socket,
          ice_agent.local_pwd
        )

      # wait so there will be a change in last_seen if something went wrong
      Process.sleep(1)

      ice_agent =
        ICEAgent.handle_udp(ice_agent, socket, remote_cand.address, remote_cand.port, resp)

      [new_pair] = Map.values(ice_agent.checklist)
      assert new_pair.last_seen == pair.last_seen
      assert new_pair.responses_received == pair.responses_received + 1
    end

    test "non-symmetric success response", %{ice_agent: ice_agent} do
      ice_agent = connect(ice_agent)

      [socket] = ice_agent.sockets
      [remote_cand] = Map.values(ice_agent.remote_cands)
      [pair] = Map.values(ice_agent.checklist)

      # trigger keepalive request
      ice_agent = ICEAgent.handle_keepalive_timeout(ice_agent, pair.id)
      assert packet = Transport.Mock.recv(socket)
      assert {:ok, req} = ExSTUN.Message.decode(packet)

      resp =
        binding_response(
          req.transaction_id,
          ice_agent.transport_module,
          socket,
          ice_agent.remote_pwd
        )

      # wait so there will be a change in last_seen if something went wrong
      Process.sleep(1)

      # modify port so that addresses are non-symmetic
      ice_agent =
        ICEAgent.handle_udp(ice_agent, socket, remote_cand.address, remote_cand.port + 1, resp)

      [new_pair] = Map.values(ice_agent.checklist)
      assert new_pair.last_seen == pair.last_seen
      assert new_pair.responses_received == pair.responses_received

      assert new_pair.non_symmetric_responses_received ==
               pair.non_symmetric_responses_received + 1
    end

    test "error response", %{ice_agent: ice_agent} do
      ice_agent = connect(ice_agent)

      [socket] = ice_agent.sockets
      [remote_cand] = Map.values(ice_agent.remote_cands)
      [pair] = Map.values(ice_agent.checklist)

      # trigger keepalive request
      ice_agent = ICEAgent.handle_keepalive_timeout(ice_agent, pair.id)
      assert packet = Transport.Mock.recv(socket)
      assert {:ok, req} = ExSTUN.Message.decode(packet)

      resp =
        Message.new(req.transaction_id, %Type{class: :error_response, method: :binding}, [
          %ErrorCode{code: 400}
        ])
        |> Message.encode()

      # wait so there will be a change in last_seen if something went wrong
      Process.sleep(1)

      ice_agent =
        ICEAgent.handle_udp(ice_agent, socket, remote_cand.address, remote_cand.port, resp)

      [new_pair] = Map.values(ice_agent.checklist)
      assert new_pair.last_seen == pair.last_seen
      assert new_pair.responses_received == pair.responses_received + 1
    end
  end

  describe "incoming binding request" do
    setup do
      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlling,
          if_discovery_module: IfDiscovery.Mock,
          transport_module: Transport.Mock
        )

      ice_agent = ICEAgent.gather_candidates(ice_agent)

      %{ice_agent: ice_agent, remote_cand: @remote_cand}
    end

    test "with correct attributes", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [socket] = ice_agent.sockets

      request =
        Message.new(%Type{class: :request, method: :binding}, [
          %Username{value: "#{ice_agent.local_ufrag}:someufrag"},
          %Priority{priority: 1234},
          %ICEControlled{tiebreaker: 1234}
        ])
        |> Message.with_integrity(ice_agent.local_pwd)
        |> Message.with_fingerprint()

      raw_request = Message.encode(request)

      ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert packet = Transport.Mock.recv(socket)
      assert {:ok, msg} = ExSTUN.Message.decode(packet)
      assert msg.type == %ExSTUN.Message.Type{class: :success_response, method: :binding}
      assert msg.transaction_id == request.transaction_id
      assert length(msg.attributes) == 3

      assert {:ok, %XORMappedAddress{address: {192, 168, 0, 2}, port: 8445}} =
               ExSTUN.Message.get_attribute(msg, XORMappedAddress)

      assert :ok == ExSTUN.Message.check_fingerprint(msg)
      assert :ok == ExSTUN.Message.authenticate(msg, ice_agent.local_pwd)
    end

    test "with use candidate", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [socket] = ice_agent.sockets

      request =
        Message.new(%Type{class: :request, method: :binding}, [
          %Username{value: "#{ice_agent.local_ufrag}:someufrag"},
          %Priority{priority: 1234},
          %ICEControlled{tiebreaker: 1234},
          %UseCandidate{}
        ])
        |> Message.with_integrity(ice_agent.local_pwd)
        |> Message.with_fingerprint()

      raw_request = Message.encode(request)

      _ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert_bad_request_error_response(socket, request)
    end

    test "with role conflict", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [socket] = ice_agent.sockets

      binding_request = fn tiebreaker ->
        Message.new(%Type{class: :request, method: :binding}, [
          %Username{value: "#{ice_agent.local_ufrag}:someufrag"},
          %Priority{priority: 1234},
          %ICEControlling{tiebreaker: tiebreaker},
          %UseCandidate{}
        ])
        |> Message.with_integrity(ice_agent.local_pwd)
        |> Message.with_fingerprint()
      end

      # feed binding request with higher tiebreaker
      request = binding_request.(ice_agent.tiebreaker + 1)
      raw_request = Message.encode(request)

      new_ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      # agent should switch its role and send success response
      assert new_ice_agent.role == :controlled
      assert new_ice_agent.tiebreaker == ice_agent.tiebreaker
      assert packet = Transport.Mock.recv(socket)
      assert {:ok, msg} = ExSTUN.Message.decode(packet)
      assert msg.type == %ExSTUN.Message.Type{class: :success_response, method: :binding}

      # feed binding request with smaller tiebreaker
      request = binding_request.(ice_agent.tiebreaker - 1)
      raw_request = Message.encode(request)

      new_ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      # agent shouldn't switch its role and should send 487 error response
      assert new_ice_agent.role == :controlling
      assert new_ice_agent.tiebreaker == ice_agent.tiebreaker
      assert packet = Transport.Mock.recv(socket)
      assert {:ok, msg} = ExSTUN.Message.decode(packet)
      assert msg.type == %ExSTUN.Message.Type{class: :error_response, method: :binding}
      assert {:ok, %ErrorCode{code: 487, reason: ""}} = Message.get_attribute(msg, ErrorCode)
    end

    test "without username", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [socket] = ice_agent.sockets

      request =
        Message.new(%Type{class: :request, method: :binding}, [
          %Priority{priority: 1234},
          %ICEControlled{tiebreaker: 1234}
        ])
        |> Message.with_integrity(ice_agent.local_pwd)
        |> Message.with_fingerprint()

      raw_request = Message.encode(request)

      _ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert_bad_request_error_response(socket, request)
    end

    test "without message-integrity", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [socket] = ice_agent.sockets

      request =
        Message.new(%Type{class: :request, method: :binding}, [
          %Username{value: "#{ice_agent.local_ufrag}:someufrag"},
          %Priority{priority: 1234},
          %ICEControlled{tiebreaker: 1234}
        ])
        |> Message.with_fingerprint()

      raw_request = Message.encode(request)

      _ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert_bad_request_error_response(socket, request)
    end

    test "without fingerprint", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [socket] = ice_agent.sockets

      request =
        Message.new(%Type{class: :request, method: :binding}, [
          %Username{value: "#{ice_agent.local_ufrag}:someufrag"},
          %Priority{priority: 1234},
          %ICEControlled{tiebreaker: 1234}
        ])
        |> Message.with_integrity(ice_agent.local_pwd)

      raw_request = Message.encode(request)

      _ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert_silently_discarded(socket)
    end

    test "without role", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [socket] = ice_agent.sockets

      request =
        Message.new(%Type{class: :request, method: :binding}, [
          %Username{value: "#{ice_agent.local_ufrag}:someufrag"},
          %Priority{priority: 1234}
        ])
        |> Message.with_integrity(ice_agent.local_pwd)
        |> Message.with_fingerprint()

      raw_request = Message.encode(request)

      _ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert_bad_request_error_response(socket, request)
    end

    test "without priority", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [socket] = ice_agent.sockets

      request =
        Message.new(%Type{class: :request, method: :binding}, [
          %Username{value: "#{ice_agent.local_ufrag}:someufrag"},
          %ICEControlled{tiebreaker: 1234}
        ])
        |> Message.with_integrity(ice_agent.local_pwd)
        |> Message.with_fingerprint()

      raw_request = Message.encode(request)

      _ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert_bad_request_error_response(socket, request)
    end

    test "with non-matching username", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [socket] = ice_agent.sockets

      request =
        Message.new(%Type{class: :request, method: :binding}, [
          %Username{value: "#{ice_agent.local_ufrag <> "1"}:someufrag"},
          %Priority{priority: 1234},
          %ICEControlled{tiebreaker: 1234}
        ])
        |> Message.with_integrity(ice_agent.local_pwd)
        |> Message.with_fingerprint()

      raw_request = Message.encode(request)

      _ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert_unauthenticated_error_response(socket, request)
    end

    test "with non-matching fingerprint", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [socket] = ice_agent.sockets

      request =
        Message.new(%Type{class: :request, method: :binding}, [
          %Username{value: "#{ice_agent.local_ufrag}:someufrag"},
          %Priority{priority: 1234},
          %ICEControlled{tiebreaker: 1234}
        ])
        |> Message.with_integrity(ice_agent.local_pwd)
        |> Message.with_fingerprint()
        |> Message.encode()

      # modify last byte to make fingerprint incorrect
      <<start::binary-size(byte_size(request) - 1), last_byte>> = request
      request = <<start::binary, last_byte + 1>>

      _ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          socket,
          remote_cand.address,
          remote_cand.port,
          request
        )

      assert_silently_discarded(socket)
    end

    test "with non-matching message integrity", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [socket] = ice_agent.sockets

      request =
        Message.new(%Type{class: :request, method: :binding}, [
          %Username{value: "#{ice_agent.local_ufrag}:someufrag"},
          %Priority{priority: 1234},
          %ICEControlled{tiebreaker: 1234}
        ])
        |> Message.with_integrity(ice_agent.local_pwd <> "1")
        |> Message.with_fingerprint()

      raw_request = Message.encode(request)

      _ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert_unauthenticated_error_response(socket, request)
    end

    test "before setting remote candidates", %{
      ice_agent: ice_agent,
      remote_cand: remote_cand
    } do
      # 1. Receive binding request from the remote side
      # 2. This will create prflx candidate, pair it with our local candidates
      # 3. Timer should not be started as we don't have remote credentials
      # 4. Set remote credentials
      # 5. Timer should be started as we have conn checks to execute and we also have remote credentials
      [socket] = ice_agent.sockets

      request =
        Message.new(%Type{class: :request, method: :binding}, [
          %Username{value: "#{ice_agent.local_ufrag}:someufrag"},
          %Priority{priority: 1234},
          %ICEControlled{tiebreaker: 1234}
        ])
        |> Message.with_integrity(ice_agent.local_pwd)
        |> Message.with_fingerprint()

      raw_request = Message.encode(request)

      ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      # flush the response
      Transport.Mock.recv(socket)

      # assert timer was not started
      refute_receive :ta_timeout

      # make sure that even if timer was started, handle_ta_timeout wouldn't try to send conn check
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
      assert nil == Transport.Mock.recv(socket)

      # set remote credentials and assert timer was started
      ice_agent = ICEAgent.set_remote_credentials(ice_agent, "remote_ufrag", "remote_pwd")
      assert_receive :ta_timeout

      # handle timer without errors
      ICEAgent.handle_ta_timeout(ice_agent)
    end

    defp assert_bad_request_error_response(socket, request) do
      assert packet = Transport.Mock.recv(socket)
      assert is_binary(packet)
      assert {:ok, msg} = ExSTUN.Message.decode(packet)
      assert msg.type == %ExSTUN.Message.Type{class: :error_response, method: :binding}
      assert msg.transaction_id == request.transaction_id
      assert length(msg.attributes) == 2

      assert {:ok, %ErrorCode{code: 400, reason: ""}} =
               ExSTUN.Message.get_attribute(msg, ErrorCode)

      assert :ok == ExSTUN.Message.check_fingerprint(msg)
    end

    defp assert_unauthenticated_error_response(socket, request) do
      assert packet = Transport.Mock.recv(socket)
      assert is_binary(packet)
      assert {:ok, msg} = ExSTUN.Message.decode(packet)
      assert msg.type == %ExSTUN.Message.Type{class: :error_response, method: :binding}
      assert msg.transaction_id == request.transaction_id
      assert length(msg.attributes) == 2

      assert {:ok, %ErrorCode{code: 401, reason: ""}} =
               ExSTUN.Message.get_attribute(msg, ErrorCode)

      assert :ok == ExSTUN.Message.check_fingerprint(msg)
    end

    defp assert_silently_discarded(socket) do
      assert nil == Transport.Mock.recv(socket)
    end
  end

  describe "incoming binding indication (keepalive)" do
    setup do
      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlling,
          if_discovery_module: IfDiscovery.Mock,
          transport_module: Transport.Mock
        )
        |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
        |> ICEAgent.gather_candidates()
        |> ICEAgent.add_remote_candidate(@remote_cand)

      %{ice_agent: ice_agent}
    end

    test "on succeeded pair", %{ice_agent: ice_agent} do
      [remote_cand] = Map.values(ice_agent.remote_cands)

      # make ice_agent connected
      ice_agent = connect(ice_agent)

      [socket] = ice_agent.sockets
      [pair_before] = Map.values(ice_agent.checklist)

      # wait so that we can observe a change in last_seen later on
      Process.sleep(1)

      # receive binding indication
      msg = binding_indication()

      ice_agent =
        ICEAgent.handle_udp(ice_agent, socket, remote_cand.address, remote_cand.port, msg)

      # assert that last_seen of the pair has changed
      [pair_after] = Map.values(ice_agent.checklist)

      assert pair_after.last_seen > pair_before.last_seen
    end

    test "on failed pair", %{ice_agent: ice_agent} do
      [remote_cand] = Map.values(ice_agent.remote_cands)
      [socket] = ice_agent.sockets

      # mark pair as failed
      [pair_before] = Map.values(ice_agent.checklist)
      pair_before = %CandidatePair{pair_before | state: :failed, valid?: false}
      ice_agent = put_in(ice_agent.checklist[pair_before.id], pair_before)

      # wait so that there is a change in last_seen in case of
      # incorrect behaviour
      Process.sleep(1)

      # receive binding indication
      msg = binding_indication()

      ice_agent =
        ICEAgent.handle_udp(ice_agent, socket, remote_cand.address, remote_cand.port, msg)

      # assert that nothing has changed
      [pair_after] = Map.values(ice_agent.checklist)
      assert pair_after.state == :failed
      assert pair_after.valid? == false
      assert pair_after.last_seen == pair_before.last_seen
    end

    test "on a pair that hasn't been checked yet", %{ice_agent: ice_agent} do
      [remote_cand] = Map.values(ice_agent.remote_cands)
      [socket] = ice_agent.sockets

      [pair_before] = Map.values(ice_agent.checklist)
      assert pair_before.last_seen == nil

      Process.sleep(1)

      # receive binding indication
      msg = binding_indication()

      ice_agent =
        ICEAgent.handle_udp(ice_agent, socket, remote_cand.address, remote_cand.port, msg)

      # assert last_seen has been set
      [pair_after] = Map.values(ice_agent.checklist)
      assert pair_after.last_seen != nil
    end
  end

  @conn_check_byte_size 92

  describe "connectivity check" do
    setup do
      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          aggressive_nomination: false,
          role: :controlling,
          if_discovery_module: IfDiscovery.Mock,
          transport_module: Transport.Mock
        )
        |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
        |> ICEAgent.gather_candidates()
        |> ICEAgent.add_remote_candidate(@remote_cand)

      %{ice_agent: ice_agent, remote_cand: @remote_cand}
    end

    test "request", %{ice_agent: ice_agent} do
      [socket] = ice_agent.sockets

      [pair] = Map.values(ice_agent.checklist)
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)

      assert packet = Transport.Mock.recv(socket)
      assert is_binary(packet)
      assert {:ok, req} = ExSTUN.Message.decode(packet)
      assert :ok == ExSTUN.Message.check_fingerprint(req)
      assert :ok == ExSTUN.Message.authenticate(req, ice_agent.remote_pwd)

      assert length(req.attributes) == 5

      assert {:ok, %Username{value: "#{ice_agent.remote_ufrag}:#{ice_agent.local_ufrag}"}} ==
               ExSTUN.Message.get_attribute(req, Username)

      assert {:ok, %ICEControlling{}} = ExSTUN.Message.get_attribute(req, ICEControlling)
      assert {:ok, %Priority{}} = ExSTUN.Message.get_attribute(req, Priority)

      assert [new_pair] = Map.values(ice_agent.checklist)
      assert new_pair.state == :in_progress
      assert new_pair.requests_sent == pair.requests_sent + 1
    end

    test "success response", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [socket] = ice_agent.sockets
      [pair] = Map.values(ice_agent.checklist)

      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)

      req = read_binding_request(socket, ice_agent.remote_pwd)

      resp =
        binding_response(
          req.transaction_id,
          ice_agent.transport_module,
          socket,
          ice_agent.remote_pwd
        )

      ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          socket,
          remote_cand.address,
          remote_cand.port,
          resp
        )

      assert [new_pair] = Map.values(ice_agent.checklist)
      assert new_pair.state == :succeeded
      assert new_pair.responses_received == pair.responses_received + 1
      assert ice_agent.state == :connected
    end

    test "success response with non-matching message integrity", %{
      ice_agent: ice_agent,
      remote_cand: remote_cand
    } do
      [socket] = ice_agent.sockets
      [pair] = Map.values(ice_agent.checklist)

      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)

      <<first_byte, rest::binary>> = ice_agent.remote_pwd
      invalid_remote_pwd = <<first_byte + 1, rest::binary>>

      req = read_binding_request(socket, ice_agent.remote_pwd)

      resp =
        binding_response(
          req.transaction_id,
          ice_agent.transport_module,
          socket,
          invalid_remote_pwd
        )

      ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          socket,
          remote_cand.address,
          remote_cand.port,
          resp
        )

      # Unauthenticated response is ignored as it was never received.
      # Hence, no impact on pair's state but we count it in the stats
      # to be able to observe that something is received.
      assert [new_pair] = Map.values(ice_agent.checklist)
      assert new_pair.state == :in_progress
      assert new_pair.responses_received == pair.responses_received + 1
    end

    test "bad request error response", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [socket] = ice_agent.sockets
      [pair] = Map.values(ice_agent.checklist)

      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)

      req = read_binding_request(socket, ice_agent.remote_pwd)

      resp =
        Message.new(req.transaction_id, %Type{class: :error_response, method: :binding}, [
          %ErrorCode{code: 400}
        ])
        |> Message.with_fingerprint()
        |> Message.encode()

      ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          socket,
          remote_cand.address,
          remote_cand.port,
          resp
        )

      assert [new_pair] = Map.values(ice_agent.checklist)
      assert new_pair.state == :failed
      assert new_pair.responses_received == pair.responses_received + 1
    end

    test "role conflict error response" do
      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlling,
          if_discovery_module: IfDiscovery.Mock,
          transport_module: Transport.Mock
        )
        |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
        |> ICEAgent.gather_candidates()
        |> ICEAgent.add_remote_candidate(@remote_cand)

      [socket] = ice_agent.sockets

      # trigger check
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
      [pair1] = Map.values(ice_agent.checklist)
      req1 = read_binding_request(socket, ice_agent.remote_pwd)

      # Add the second candidate and trigger another check.
      # We add candidate after generating the first check to be sure
      # it is related to @remote_cand2.
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, @remote_cand2)
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
      [pair2] = Map.values(ice_agent.checklist) |> Enum.reject(&(&1.id == pair1.id))
      req2 = read_binding_request(socket, ice_agent.remote_pwd)

      # reply to the first check with role conflict error response
      resp =
        Message.new(req1.transaction_id, %Type{class: :error_response, method: :binding}, [
          %ErrorCode{code: 487}
        ])
        |> Message.with_integrity(ice_agent.remote_pwd)
        |> Message.with_fingerprint()
        |> Message.encode()

      new_ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          socket,
          @remote_cand.address,
          @remote_cand.port,
          resp
        )

      # assert that the agent changed its role and tiebreaker
      assert new_ice_agent.role != ice_agent.role
      assert new_ice_agent.tiebreaker != ice_agent.tiebreaker
      assert Map.fetch!(new_ice_agent.checklist, pair1.id).state == :waiting

      # reply to the second check with role conflict error response
      resp =
        Message.new(req2.transaction_id, %Type{class: :error_response, method: :binding}, [
          %ErrorCode{code: 487}
        ])
        |> Message.with_integrity(new_ice_agent.remote_pwd)
        |> Message.with_fingerprint()
        |> Message.encode()

      new_ice_agent2 =
        ICEAgent.handle_udp(
          new_ice_agent,
          socket,
          @remote_cand2.address,
          @remote_cand2.port,
          resp
        )

      # assert that agent didn't switch its role and tiebreaker
      assert new_ice_agent2.role == new_ice_agent.role
      assert new_ice_agent2.tiebreaker == new_ice_agent.tiebreaker
      assert Map.fetch!(new_ice_agent2.checklist, pair2.id).state == :waiting
    end

    test "unauthenticated error response", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [socket] = ice_agent.sockets
      [pair] = Map.values(ice_agent.checklist)

      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)

      req = read_binding_request(socket, ice_agent.remote_pwd)

      resp =
        Message.new(req.transaction_id, %Type{class: :error_response, method: :binding}, [
          %ErrorCode{code: 401}
        ])
        |> Message.with_fingerprint()
        |> Message.encode()

      ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          socket,
          remote_cand.address,
          remote_cand.port,
          resp
        )

      assert [new_pair] = Map.values(ice_agent.checklist)
      assert new_pair.state == :failed
      assert new_pair.responses_received == pair.responses_received + 1
    end

    test "response from non-symmetric address", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [socket] = ice_agent.sockets
      [pair] = Map.values(ice_agent.checklist)

      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)

      req = read_binding_request(socket, ice_agent.remote_pwd)

      resp =
        binding_response(
          req.transaction_id,
          ice_agent.transport_module,
          socket,
          ice_agent.remote_pwd
        )

      {a, b, c, d} = remote_cand.address

      ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          socket,
          {a, b, c, d + 1},
          remote_cand.port + 1,
          resp
        )

      assert [%CandidatePair{state: :failed}] = Map.values(ice_agent.checklist)
      assert [new_pair] = Map.values(ice_agent.checklist)
      assert new_pair.state == :failed
      assert new_pair.responses_received == pair.responses_received

      assert new_pair.non_symmetric_responses_received ==
               pair.non_symmetric_responses_received + 1
    end

    test "concluding", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [socket] = ice_agent.sockets

      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)

      req = read_binding_request(socket, ice_agent.remote_pwd)

      resp =
        binding_response(
          req.transaction_id,
          ice_agent.transport_module,
          socket,
          ice_agent.remote_pwd
        )

      ice_agent =
        ICEAgent.handle_udp(ice_agent, socket, remote_cand.address, remote_cand.port, resp)

      assert ice_agent.state == :connected

      # assert that setting end-of-candidates triggers nomination check and concludes ICE
      ice_agent = ICEAgent.end_of_candidates(ice_agent)
      assert ice_agent.state == :connected
      req = read_binding_request(socket, ice_agent.remote_pwd)

      resp =
        binding_response(
          req.transaction_id,
          ice_agent.transport_module,
          socket,
          ice_agent.remote_pwd
        )

      ice_agent =
        ICEAgent.handle_udp(ice_agent, socket, remote_cand.address, remote_cand.port, resp)

      assert ice_agent.state == :completed
    end

    test "failure on send" do
      # 1. replace candidate with the mock one that always fails to send data
      # 2. assert that after unsuccessful conn check sending, ice_agent moves conn pair to the failed state

      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlling,
          if_discovery_module: IfDiscovery.Mock,
          transport_module: Transport.Mock
        )
        |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
        |> ICEAgent.gather_candidates()
        |> ICEAgent.add_remote_candidate(@remote_cand)
        |> ICEAgent.end_of_candidates()

      assert ice_agent.gathering_state == :complete

      # replace candidate with the mock one
      [local_cand] = Map.values(ice_agent.local_cands)
      mock_cand = %Candidate.Mock{base: local_cand.base}
      ice_agent = %{ice_agent | local_cands: %{mock_cand.base.id => mock_cand}}

      # try to send conn check
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)

      assert ice_agent.state == :checking

      # assert that the candidate pair has moved to a failed state
      # and that the state was updated after the packet was discarded
      assert [
               %{
                 state: :failed,
                 valid?: false,
                 packets_discarded_on_send: 1,
                 bytes_discarded_on_send: @conn_check_byte_size
               }
             ] = Map.values(ice_agent.checklist)

      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)

      assert ice_agent.state == :failed
    end
  end

  describe "connectivity check with aggressive nomination" do
    setup do
      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlling,
          aggressive_nomination: true,
          if_discovery_module: IfDiscovery.Mock,
          transport_module: Transport.Mock
        )
        |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
        |> ICEAgent.gather_candidates()

      %{ice_agent: ice_agent}
    end

    test "request", %{ice_agent: ice_agent} do
      rcand1 = ExICE.Candidate.new(:srflx, address: {192, 168, 0, 2}, port: 8445, priority: 123)
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, rcand1)

      [socket] = ice_agent.sockets

      [pair] = Map.values(ice_agent.checklist)
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)

      assert packet = Transport.Mock.recv(socket)
      assert is_binary(packet)
      assert {:ok, req} = ExSTUN.Message.decode(packet)
      assert :ok == ExSTUN.Message.check_fingerprint(req)
      assert :ok == ExSTUN.Message.authenticate(req, ice_agent.remote_pwd)

      assert length(req.attributes) == 6

      assert {:ok, %Username{value: "#{ice_agent.remote_ufrag}:#{ice_agent.local_ufrag}"}} ==
               ExSTUN.Message.get_attribute(req, Username)

      assert {:ok, %ICEControlling{}} = ExSTUN.Message.get_attribute(req, ICEControlling)
      assert {:ok, %Priority{}} = ExSTUN.Message.get_attribute(req, Priority)
      assert {:ok, %UseCandidate{}} = ExSTUN.Message.get_attribute(req, UseCandidate)

      assert [new_pair] = Map.values(ice_agent.checklist)
      assert new_pair.state == :in_progress
      assert new_pair.requests_sent == pair.requests_sent + 1
    end

    test "success response", %{ice_agent: ice_agent} do
      rcand1 = ExICE.Candidate.new(:srflx, address: {192, 168, 0, 2}, port: 8445, priority: 122)
      rcand2 = ExICE.Candidate.new(:host, address: {192, 168, 0, 3}, port: 8445, priority: 123)

      ice_agent = ICEAgent.add_remote_candidate(ice_agent, rcand1)

      [socket] = ice_agent.sockets

      # execute cc on srflx cand
      [srflx_pair] = Map.values(ice_agent.checklist)
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)

      req = read_binding_request(socket, ice_agent.remote_pwd)

      resp =
        binding_response(
          req.transaction_id,
          ice_agent.transport_module,
          socket,
          ice_agent.remote_pwd
        )

      ice_agent = ICEAgent.handle_udp(ice_agent, socket, rcand1.address, rcand1.port, resp)

      # make sure that ICE has not moved to the completed state
      assert ice_agent.state == :connected
      assert [new_srflx_pair] = Map.values(ice_agent.checklist)
      assert new_srflx_pair.state == :succeeded
      assert new_srflx_pair.nominated? == true
      assert new_srflx_pair.responses_received == srflx_pair.responses_received + 1
      assert ice_agent.selected_pair_id == new_srflx_pair.id

      # execut cc on host cand
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, rcand2)
      [host_pair] = Map.values(ice_agent.checklist) |> Enum.filter(&(&1.id != srflx_pair.id))
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)

      req = read_binding_request(socket, ice_agent.remote_pwd)

      resp =
        binding_response(
          req.transaction_id,
          ice_agent.transport_module,
          socket,
          ice_agent.remote_pwd
        )

      ice_agent = ICEAgent.handle_udp(ice_agent, socket, rcand2.address, rcand2.port, resp)

      assert [new_host_pair] =
               Map.values(ice_agent.checklist) |> Enum.filter(&(&1.id != srflx_pair.id))

      assert new_host_pair.state == :succeeded
      assert new_host_pair.nominated? == true
      assert new_host_pair.responses_received == host_pair.responses_received + 1
      assert ice_agent.selected_pair_id == new_host_pair.id
    end

    test "success response after setting eoc and finishing candidate gathering", %{
      ice_agent: ice_agent
    } do
      # this test checks if we move from checking directly to complete
      # when eoc is set and local candidates gathering has finished

      rcand1 = ExICE.Candidate.new(:host, address: {192, 168, 0, 2}, port: 8445, priority: 123)

      ice_agent =
        ice_agent
        |> ICEAgent.add_remote_candidate(rcand1)
        |> ICEAgent.end_of_candidates()

      [socket] = ice_agent.sockets

      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)

      req = read_binding_request(socket, ice_agent.remote_pwd)

      resp =
        binding_response(
          req.transaction_id,
          ice_agent.transport_module,
          socket,
          ice_agent.remote_pwd
        )

      assert ice_agent.state == :checking
      ice_agent = ICEAgent.handle_udp(ice_agent, socket, rcand1.address, rcand1.port, resp)
      assert ice_agent.state == :completed
    end

    test "concluding", %{ice_agent: ice_agent} do
      rcand1 = ExICE.Candidate.new(:host, address: {192, 168, 0, 2}, port: 8445, priority: 123)

      ice_agent = ICEAgent.add_remote_candidate(ice_agent, rcand1)

      [socket] = ice_agent.sockets

      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)

      req = read_binding_request(socket, ice_agent.remote_pwd)

      resp =
        binding_response(
          req.transaction_id,
          ice_agent.transport_module,
          socket,
          ice_agent.remote_pwd
        )

      ice_agent = ICEAgent.handle_udp(ice_agent, socket, rcand1.address, rcand1.port, resp)

      assert ice_agent.state == :connected

      # assert that setting end-of-candidates flag concludes ice
      # and there is no additional conn check sent (as we use aggressive nomination)
      ice_agent = ICEAgent.end_of_candidates(ice_agent)
      assert ice_agent.state == :completed
      assert Transport.Mock.recv(socket) == nil
    end
  end

  defp read_binding_request(socket, remote_pwd) do
    packet = Transport.Mock.recv(socket)
    {:ok, req} = ExSTUN.Message.decode(packet)
    :ok = ExSTUN.Message.authenticate(req, remote_pwd)
    req
  end

  describe "connectivity check rtx" do
    setup do
      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlling,
          if_discovery_module: IfDiscovery.Mock,
          transport_module: Transport.Mock
        )
        |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
        |> ICEAgent.gather_candidates()
        |> ICEAgent.add_remote_candidate(@remote_cand)

      %{ice_agent: ice_agent, remote_cand: @remote_cand}
    end

    test "retransmits cc when there is no response", %{
      ice_agent: ice_agent,
      remote_cand: remote_cand
    } do
      [socket] = ice_agent.sockets

      # trigger binding request
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
      [pair] = Map.values(ice_agent.checklist)
      raw_req = Transport.Mock.recv(socket)
      assert raw_req != nil
      {:ok, req} = ExSTUN.Message.decode(raw_req)

      # trigger rtx timeout
      ice_agent = ICEAgent.handle_tr_rtx_timeout(ice_agent, req.transaction_id)
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
      rtx_raw_req = Transport.Mock.recv(socket)

      # assert this is exactly the same message
      assert raw_req == rtx_raw_req

      # assert that requests_sent is not incremented as it does not count retransmissions
      [new_pair] = Map.values(ice_agent.checklist)
      assert new_pair.requests_sent == pair.requests_sent

      # provide a response and ensure no more retransmissions are sent
      raw_resp =
        binding_response(
          req.transaction_id,
          ice_agent.transport_module,
          socket,
          ice_agent.remote_pwd
        )

      ice_agent =
        ICEAgent.handle_udp(ice_agent, socket, remote_cand.address, remote_cand.port, raw_resp)

      ice_agent = ICEAgent.handle_tr_rtx_timeout(ice_agent, req.transaction_id)
      _ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
      assert nil == Transport.Mock.recv(socket)
    end

    test "stop retransmissions when pair times out", %{ice_agent: ice_agent} do
      [socket] = ice_agent.sockets

      # trigger binding request
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
      raw_req = Transport.Mock.recv(socket)
      assert raw_req != nil
      {:ok, req} = ExSTUN.Message.decode(raw_req)

      # trigger rtx timeout
      ice_agent = ICEAgent.handle_tr_rtx_timeout(ice_agent, req.transaction_id)
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
      assert nil != Transport.Mock.recv(socket)

      # mock cc send time so we can timeout it
      [cc] = Map.values(ice_agent.conn_checks)
      cc = %{cc | send_time: cc.send_time - 2000}
      ice_agent = put_in(ice_agent.conn_checks[req.transaction_id], cc)

      # timeout cc
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
      assert %{} == ice_agent.conn_checks

      # trigger rtx timeout and assert there is no retransmission
      ice_agent = ICEAgent.handle_tr_rtx_timeout(ice_agent, req.transaction_id)
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
      assert nil == Transport.Mock.recv(socket)
      assert [] == ice_agent.tr_rtx
    end
  end

  describe "srflx gathering tr rtx" do
    setup do
      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlling,
          if_discovery_module: IfDiscovery.Mock,
          transport_module: Transport.Mock,
          ice_servers: [%{urls: ["stun:192.168.0.10:8445"]}]
        )

      %{ice_agent: ice_agent, stun_addr: %{ip: {192, 168, 0, 10}, port: 8445}}
    end

    test "retransmits tr when there is no response", %{ice_agent: ice_agent, stun_addr: stun_addr} do
      ice_agent = ICEAgent.gather_candidates(ice_agent)
      [socket] = ice_agent.sockets

      # trigger binding request
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
      raw_req = Transport.Mock.recv(socket)
      assert raw_req != nil
      {:ok, req} = ExSTUN.Message.decode(raw_req)

      # trigger rtx timeout
      ice_agent = ICEAgent.handle_tr_rtx_timeout(ice_agent, req.transaction_id)
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
      rtx_raw_req = Transport.Mock.recv(socket)

      # assert this is exactly the same message
      assert raw_req == rtx_raw_req

      # provide a response and ensure no more retransmissions are sent
      {:ok, {sock_ip, sock_port}} = ice_agent.transport_module.sockname(socket)

      raw_resp =
        Message.new(req.transaction_id, %Type{class: :success_response, method: :binding}, [
          %XORMappedAddress{address: sock_ip, port: sock_port}
        ])
        |> Message.with_fingerprint()
        |> Message.encode()

      ice_agent = ICEAgent.handle_udp(ice_agent, socket, stun_addr.ip, stun_addr.port, raw_resp)

      ice_agent = ICEAgent.handle_tr_rtx_timeout(ice_agent, req.transaction_id)
      _ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
      assert nil == Transport.Mock.recv(socket)
    end

    test "stop retransmissions when tr times out", %{ice_agent: ice_agent} do
      ice_agent = ICEAgent.gather_candidates(ice_agent)
      [socket] = ice_agent.sockets

      # trigger binding request
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
      raw_req = Transport.Mock.recv(socket)
      assert raw_req != nil
      {:ok, req} = ExSTUN.Message.decode(raw_req)

      # trigger rtx timeout
      ice_agent = ICEAgent.handle_tr_rtx_timeout(ice_agent, req.transaction_id)
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
      assert nil != Transport.Mock.recv(socket)

      # mock tr send time so we can timeout it
      [tr] = Map.values(ice_agent.gathering_transactions)
      tr = %{tr | send_time: tr.send_time - 2000}
      ice_agent = put_in(ice_agent.gathering_transactions[req.transaction_id], tr)

      # timeout tr
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
      assert %{} == ice_agent.gathering_transactions

      # trigger rtx timeout and assert there is no retransmission
      ice_agent = ICEAgent.handle_tr_rtx_timeout(ice_agent, req.transaction_id)
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
      assert nil == Transport.Mock.recv(socket)
      assert [] == ice_agent.tr_rtx
    end
  end

  test "pair timeout" do
    # 1. make ice agent connected
    # 2. mock the time a pair has received something from the peer
    # 3. trigger pair timeout
    # 4. assert that the pair has been marked as failed
    # 5. trigger eoc timeout and assert that ice agent moved to the failed state

    ice_agent =
      ICEAgent.new(
        controlling_process: self(),
        role: :controlling,
        if_discovery_module: IfDiscovery.Mock,
        transport_module: Transport.Mock
      )
      |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
      |> ICEAgent.gather_candidates()
      |> ICEAgent.add_remote_candidate(@remote_cand)

    # Make sure we are not gathering local candidates.
    # That's important for moving to the failed state later on.
    assert ice_agent.gathering_state == :complete

    # make ice_agent connected
    ice_agent = connect(ice_agent)

    # mock last_seen field
    [pair] = Map.values(ice_agent.checklist)
    last_seen = System.monotonic_time(:millisecond) - 10_000
    pair = %{pair | last_seen: last_seen}
    ice_agent = put_in(ice_agent.checklist[pair.id], pair)

    # trigger pair timeout
    ice_agent = ICEAgent.handle_pair_timeout(ice_agent)

    # assert that the pair is marked as failed
    assert [%CandidatePair{state: :failed}] = Map.values(ice_agent.checklist)

    # trigger eoc timeout
    ice_agent = ICEAgent.handle_eoc_timeout(ice_agent)

    # assert ice agent moved to the failed state
    assert ice_agent.state == :failed
  end

  test "agent state and behavior after it fails" do
    ice_agent =
      ICEAgent.new(
        controlling_process: self(),
        role: :controlling,
        transport_module: Transport.Mock,
        if_discovery_module: IfDiscovery.Mock
      )
      |> ICEAgent.set_remote_credentials("remoteufrag", "remotepwd")
      |> ICEAgent.gather_candidates()
      |> ICEAgent.add_remote_candidate(@remote_cand)

    # assert initial state, just to be sure it's correct before we move further
    assert map_size(ice_agent.local_cands) == 1
    assert map_size(ice_agent.remote_cands) == 1
    assert map_size(ice_agent.checklist) == 1

    ice_agent = connect(ice_agent)

    # mark pair as failed
    [pair] = Map.values(ice_agent.checklist)
    ice_agent = put_in(ice_agent.checklist[pair.id], %{pair | state: :failed})

    # set eoc flag
    failed_ice_agent = ICEAgent.end_of_candidates(ice_agent)

    # agent should have moved to the failed state
    assert failed_ice_agent.state == :failed
    assert failed_ice_agent.sockets == ice_agent.sockets
    assert [%{base: %{closed?: true}}] = Map.values(failed_ice_agent.local_cands)
    assert failed_ice_agent.remote_cands == ice_agent.remote_cands
    assert failed_ice_agent.gathering_transactions == %{}
    assert failed_ice_agent.selected_pair_id == nil
    assert failed_ice_agent.conn_checks == %{}
    assert failed_ice_agent.keepalives == %{}
    assert failed_ice_agent.tr_rtx == []
    assert failed_ice_agent.checklist == ice_agent.checklist
    assert failed_ice_agent.local_ufrag == ice_agent.local_ufrag
    assert failed_ice_agent.local_pwd == ice_agent.local_pwd
    assert failed_ice_agent.remote_ufrag == ice_agent.remote_ufrag
    assert failed_ice_agent.remote_pwd == ice_agent.remote_pwd
    assert failed_ice_agent.eoc == true
    assert failed_ice_agent.nominating? == {false, nil}

    [socket] = ice_agent.sockets

    # assert that handle_udp ignores incoming data i.e. the state of ice agent didn't change
    new_ice_agent =
      ICEAgent.handle_udp(
        failed_ice_agent,
        socket,
        @remote_cand.address,
        @remote_cand.port,
        "some data"
      )

    assert failed_ice_agent == new_ice_agent

    # the same with incoming binding request
    req =
      binding_request(
        failed_ice_agent.role,
        failed_ice_agent.tiebreaker,
        "remoteufrag",
        failed_ice_agent.local_ufrag,
        failed_ice_agent.local_pwd
      )

    new_ice_agent =
      ICEAgent.handle_udp(failed_ice_agent, socket, @remote_cand.address, @remote_cand.port, req)

    assert failed_ice_agent == new_ice_agent

    # and handle_ta_timeout
    new_ice_agent = ICEAgent.handle_ta_timeout(failed_ice_agent)
    assert failed_ice_agent == new_ice_agent
  end

  test "agent state and behavior after it completes" do
    r_cand1 = ExICE.Candidate.new(:host, address: {192, 168, 0, 3}, port: 8445, priority: 123)
    r_cand2 = ExICE.Candidate.new(:srflx, address: {192, 168, 0, 4}, port: 8445, priority: 120)
    r_cand3 = ExICE.Candidate.new(:srflx, address: {192, 168, 0, 5}, port: 8445, priority: 119)

    ice_agent =
      ICEAgent.new(
        controlling_process: self(),
        role: :controlled,
        transport_module: Transport.Mock,
        if_discovery_module: IfDiscovery.Mock
      )
      |> ICEAgent.set_remote_credentials("remoteufrag", "remotepwd")
      |> ICEAgent.gather_candidates()
      |> ICEAgent.add_remote_candidate(r_cand1)

    [socket] = ice_agent.sockets

    raw_req =
      binding_request(
        ice_agent.role,
        ice_agent.tiebreaker,
        "remoteufrag",
        ice_agent.local_ufrag,
        ice_agent.local_pwd
      )

    ice_agent = ICEAgent.handle_udp(ice_agent, socket, r_cand1.address, r_cand1.port, raw_req)
    # read binding response
    _ = Transport.Mock.recv(socket)
    # assert there is nothing else on socket
    assert nil == Transport.Mock.recv(socket)

    # execute conn-check
    ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
    assert req = Transport.Mock.recv(socket)
    {:ok, req} = ExSTUN.Message.decode(req)

    resp = binding_response(req.transaction_id, ice_agent.transport_module, socket, "remotepwd")
    ice_agent = ICEAgent.handle_udp(ice_agent, socket, r_cand1.address, r_cand1.port, resp)

    # add second candidate and repeat
    ice_agent = ICEAgent.add_remote_candidate(ice_agent, r_cand2)
    ice_agent = ICEAgent.handle_udp(ice_agent, socket, r_cand2.address, r_cand2.port, raw_req)
    _ = Transport.Mock.recv(socket)
    assert nil == Transport.Mock.recv(socket)

    ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
    assert req = Transport.Mock.recv(socket)
    {:ok, req} = ExSTUN.Message.decode(req)
    resp = binding_response(req.transaction_id, ice_agent.transport_module, socket, "remotepwd")
    ice_agent = ICEAgent.handle_udp(ice_agent, socket, r_cand2.address, r_cand2.port, resp)

    # add third candidate but with error response
    ice_agent = ICEAgent.add_remote_candidate(ice_agent, r_cand3)
    ice_agent = ICEAgent.handle_udp(ice_agent, socket, r_cand3.address, r_cand3.port, raw_req)
    _ = Transport.Mock.recv(socket)
    assert nil == Transport.Mock.recv(socket)

    ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
    assert req = Transport.Mock.recv(socket)
    {:ok, req} = ExSTUN.Message.decode(req)

    resp =
      Message.new(req.transaction_id, %Type{class: :error_response, method: :binding}, [
        %ErrorCode{code: 400}
      ])
      |> Message.encode()

    ice_agent = ICEAgent.handle_udp(ice_agent, socket, r_cand3.address, r_cand3.port, resp)

    # assert ice agent is connected, and it has two succeeded pairs and one failed pair
    assert :connected == ice_agent.state

    assert [:succeeded, :succeeded, :failed] --
             Enum.map(ice_agent.checklist, fn {_id, pair} -> pair.state end) == []

    # set end-of-candidates
    ice_agent = ICEAgent.end_of_candidates(ice_agent)

    # assert ice agent changed its state to completed
    # and it still has three pairs and three remote candidates
    assert ice_agent.state == :completed

    assert [:succeeded, :succeeded, :failed] --
             Enum.map(ice_agent.checklist, fn {_id, pair} -> pair.state end) == []

    # Because this test simulates aggressive nomination, two pairs will be nominated.
    assert [true, true, false] --
             Enum.map(ice_agent.checklist, fn {_id, pair} -> pair.nominated? end) == []

    assert map_size(ice_agent.local_cands) == 1
    assert map_size(ice_agent.remote_cands) == 3

    # try to feed data from the srflx remote cand - it should be accepted
    ice_agent =
      ICEAgent.handle_udp(ice_agent, socket, r_cand2.address, r_cand2.port, "some data")

    assert_receive {:ex_ice, _pid, {:data, "some data"}}

    # try to handle keepalive on the srflx pair, it should be ignored
    {_id, srflx_pair} =
      Enum.find(ice_agent.checklist, fn {_pair_id, pair} -> pair.remote_cand_id == r_cand2.id end)

    new_ice_agent = ICEAgent.handle_keepalive_timeout(ice_agent, srflx_pair.id)
    assert ice_agent == new_ice_agent

    # try to handle binding request on failed pair, it should be ignored
    req =
      binding_request(
        ice_agent.role,
        ice_agent.tiebreaker,
        "remoteufrag",
        ice_agent.local_ufrag,
        ice_agent.local_pwd
      )

    new_ice_agent = ICEAgent.handle_udp(ice_agent, socket, r_cand3.address, r_cand3.port, req)

    # assert we still have two succeeded and one failed pair
    assert [:succeeded, :succeeded, :failed] --
             Enum.map(new_ice_agent.checklist, fn {_id, pair} -> pair.state end) == []

    # assert there is no response
    assert nil == Transport.Mock.recv(socket)

    # try to handle binding request from unknown remote candidate
    prflx_cand = ExICE.Candidate.new(:prflx, address: {192, 168, 0, 6}, port: 8445, priority: 122)

    new_ice_agent =
      ICEAgent.handle_udp(ice_agent, socket, prflx_cand.address, prflx_cand.port, req)

    # assert there is a new prflx candidate but the checklist remains the same
    # In theory, we could even ignore this candidate, but this would require some changes
    # in the code base architecture.
    [%ExICE.Candidate{type: :prflx}] =
      Map.values(new_ice_agent.remote_cands) -- Map.values(ice_agent.remote_cands)

    assert new_ice_agent.checklist == ice_agent.checklist
  end

  @stun_ip {192, 168, 0, 3}
  @stun_ip_str :inet.ntoa(@stun_ip)
  @stun_port 19_302

  describe "gather srflx candidates" do
    setup do
      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlling,
          transport_module: Transport.Mock,
          if_discovery_module: IfDiscovery.Mock,
          ice_servers: [%{urls: "stun:#{@stun_ip_str}:#{@stun_port}"}]
        )
        |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
        |> ICEAgent.gather_candidates()

      [socket] = ice_agent.sockets

      # assert no transactions are started until handle_ta_timeout is called
      assert nil == Transport.Mock.recv(socket)

      %{ice_agent: ice_agent}
    end

    test "success response", %{ice_agent: ice_agent} do
      [socket] = ice_agent.sockets
      {:ok, {_sock_ip, sock_port}} = ice_agent.transport_module.sockname(socket)
      srflx_ip = {192, 168, 0, 2}
      srflx_port = sock_port + 1

      # assert ice agent started gathering transaction by sending a binding request
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
      assert packet = Transport.Mock.recv(socket)
      assert {:ok, req} = ExSTUN.Message.decode(packet)
      assert req.type.class == :request
      assert req.type.method == :binding

      resp =
        Message.new(req.transaction_id, %Type{class: :success_response, method: :binding}, [
          %XORMappedAddress{address: srflx_ip, port: srflx_port}
        ])
        |> Message.encode()

      ice_agent =
        ICEAgent.handle_udp(ice_agent, socket, @stun_ip, @stun_port, resp)

      # assert there is a new, srflx candidate
      assert %ExICE.Priv.Candidate.Srflx{} =
               srflx_cand =
               ice_agent.local_cands
               |> Map.values()
               |> Enum.find(&(&1.base.type == :srflx))

      assert srflx_cand.base.address == srflx_ip
      assert srflx_cand.base.port == srflx_port
      assert ice_agent.gathering_transactions == %{}
    end

    test "error response", %{ice_agent: ice_agent} do
      [socket] = ice_agent.sockets

      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)

      assert packet = Transport.Mock.recv(socket)
      assert {:ok, req} = ExSTUN.Message.decode(packet)

      resp =
        Message.new(req.transaction_id, %Type{class: :error_response, method: :binding}, [
          %ErrorCode{code: 400}
        ])
        |> Message.encode()

      ice_agent =
        ICEAgent.handle_udp(ice_agent, socket, @stun_ip, @stun_port, resp)

      # assert there are no new srflx candidates
      assert nil ==
               ice_agent.local_cands
               |> Map.values()
               |> Enum.find(&(&1.base.type == :srflx))

      assert ice_agent.gathering_transactions == %{}
    end
  end

  @turn_ip {192, 168, 0, 3}
  @turn_ip_str :inet.ntoa(@turn_ip)
  @turn_port 19_302
  @turn_relay_ip {192, 168, 0, 3}
  @turn_relay_port 12_345
  @turn_realm "testrealm"
  @turn_nonce "testnonce"
  @turn_username "testusername"
  @turn_password "testpassword"

  describe "gather relay candidates" do
    setup do
      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlling,
          transport_module: Transport.Mock,
          if_discovery_module: IfDiscovery.Mock,
          ice_transport_policy: :relay,
          ice_servers: [
            %{
              urls: "turn:#{@turn_ip_str}:#{@turn_port}?transport=udp",
              username: @turn_username,
              credential: @turn_password
            }
          ]
        )
        |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
        |> ICEAgent.gather_candidates()

      ice_agent = ICEAgent.add_remote_candidate(ice_agent, @remote_cand)

      [socket] = ice_agent.sockets

      # assert no transactions are started until handle_ta_timeout is called
      assert nil == Transport.Mock.recv(socket)

      %{ice_agent: ice_agent}
    end

    test "success response", %{ice_agent: ice_agent} do
      [socket] = ice_agent.sockets

      # assert ice agent started gathering transaction by sending an allocate request
      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
      req = read_allocate_request(socket)

      # TURN uses long-term authentication mechanism
      # where the first response is an error response with
      # attributes that client will use in the next request
      resp = allocate_error_response(req.transaction_id)
      ice_agent = ICEAgent.handle_udp(ice_agent, socket, @turn_ip, @turn_port, resp)

      # assert ice agent repeats an allocate request
      req = read_allocate_request(socket)

      # reply with allocate success response
      resp = allocate_success_response(req.transaction_id, ice_agent.transport_module, socket)
      ice_agent = ICEAgent.handle_udp(ice_agent, socket, @turn_ip, @turn_port, resp)

      # assert there is a new relay candidate
      assert %ExICE.Priv.Candidate.Relay{} =
               relay_cand =
               ice_agent.local_cands
               |> Map.values()
               |> Enum.find(&(&1.base.type == :relay))

      assert relay_cand.base.address == @turn_relay_ip
      assert relay_cand.base.port == @turn_relay_port
      assert ice_agent.gathering_transactions == %{}

      # assert there is a new pair
      assert [%CandidatePair{} = pair] = Map.values(ice_agent.checklist)
      assert pair.local_cand_id == relay_cand.base.id
    end

    test "error response", %{ice_agent: ice_agent} do
      [socket] = ice_agent.sockets

      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)

      req = read_allocate_request(socket)

      resp = allocate_error_response(req.transaction_id)

      ice_agent = ICEAgent.handle_udp(ice_agent, socket, @turn_ip, @turn_port, resp)

      req = read_allocate_request(socket)

      # reply with allocate error response
      resp =
        Message.new(req.transaction_id, %Type{class: :error_response, method: :allocate}, [
          # allocation quota reached
          %ErrorCode{code: 486}
        ])
        |> Message.with_integrity(Message.lt_key(@turn_username, @turn_password, @turn_realm))
        |> Message.encode()

      ice_agent = ICEAgent.handle_udp(ice_agent, socket, @turn_ip, @turn_port, resp)

      # assert there isn't a new relay candidate
      assert nil ==
               ice_agent.local_cands
               |> Map.values()
               |> Enum.find(&(&1.base.type == :relay))

      assert ice_agent.gathering_transactions == %{}
    end

    test "invalid response", %{ice_agent: ice_agent} do
      [socket] = ice_agent.sockets

      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)

      req = read_allocate_request(socket)

      resp = allocate_error_response(req.transaction_id)

      ice_agent = ICEAgent.handle_udp(ice_agent, socket, @turn_ip, @turn_port, resp)

      req = read_allocate_request(socket)

      # reply with invalid response (no attributes)
      resp =
        Message.new(req.transaction_id, %Type{class: :success_response, method: :allocate}, [])
        |> Message.with_integrity(Message.lt_key(@turn_username, @turn_password, @turn_realm))
        |> Message.encode()

      ice_agent =
        ICEAgent.handle_udp(ice_agent, socket, @turn_ip, @turn_port, resp)

      # assert there isn't a new relay candidate
      assert nil ==
               ice_agent.local_cands
               |> Map.values()
               |> Enum.find(&(&1.base.type == :relay))

      # assert gathering transaction is still in-progress
      turn_tr_id = {socket, {@turn_ip, @turn_port}}
      assert ice_agent.gathering_transactions[turn_tr_id].state == :in_progress

      # TODO reply with correct response and assert there is a new relay-cand
      # after fixing https://github.com/elixir-webrtc/ex_turn/issues/3
    end

    test "ex_turn timeout", %{ice_agent: ice_agent} do
      [socket] = ice_agent.sockets

      ice_agent = ICEAgent.handle_ta_timeout(ice_agent)

      req = read_allocate_request(socket)

      resp = allocate_error_response(req.transaction_id)

      ice_agent = ICEAgent.handle_udp(ice_agent, socket, @turn_ip, @turn_port, resp)

      req = read_allocate_request(socket)

      turn_tr_id = {socket, {@turn_ip, @turn_port}}
      tr = Map.fetch!(ice_agent.gathering_transactions, turn_tr_id)

      ice_agent =
        ICEAgent.handle_ex_turn_msg(
          ice_agent,
          tr.client.ref,
          {:transaction_timeout, req.transaction_id}
        )

      # assert gathering transaction failed
      assert ice_agent.gathering_transactions == %{}
    end

    test "invalid TURN URL" do
      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlling,
          transport_module: Transport.Mock,
          if_discovery_module: IfDiscovery.Mock,
          ice_servers: [
            %{
              urls: "turn:invalid.turn.url:#{@turn_port}?transport=udp",
              username: @turn_username,
              credential: @turn_password
            }
          ]
        )
        |> ICEAgent.set_remote_credentials("someufrag", "somepwd")

      assert %ICEAgent{gathering_state: :complete} = ICEAgent.gather_candidates(ice_agent)
    end

    test "non-matching IP families" do
      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlling,
          transport_module: Transport.Mock,
          if_discovery_module: IfDiscovery.IPV6.Mock,
          ice_servers: [
            %{
              urls: "turn:#{@turn_ip_str}:#{@turn_port}?transport=udp",
              username: @turn_username,
              credential: @turn_password
            }
          ]
        )
        |> ICEAgent.set_remote_credentials("someufrag", "somepwd")

      assert %ICEAgent{gathering_state: :complete} = ICEAgent.gather_candidates(ice_agent)
    end
  end

  test "relay ice_transport_policy" do
    ice_agent =
      ICEAgent.new(
        controlling_process: self(),
        role: :controlling,
        transport_module: Transport.Mock,
        if_discovery_module: IfDiscovery.Mock,
        ice_servers: [%{urls: "stun:192.168.0.3:19302"}],
        ice_transport_policy: :relay
      )
      |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
      |> ICEAgent.gather_candidates()

    assert %{} == ice_agent.local_cands
    assert %{} == ice_agent.gathering_transactions
    assert [_socket] = ice_agent.sockets
    assert ice_agent.gathering_state == :complete
  end

  test "candidate fails to send data when ice is connected" do
    # 1. make ice agent connected
    # 2. replace candidate with the mock one that always fails to send  data
    # 3. assert that after unsuccessful data sending, ice_agent doesn't move to the failed state
    # even when there is only one pair

    ice_agent =
      ICEAgent.new(
        controlling_process: self(),
        role: :controlling,
        if_discovery_module: IfDiscovery.Mock,
        transport_module: Transport.Mock
      )
      |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
      |> ICEAgent.gather_candidates()
      |> ICEAgent.add_remote_candidate(@remote_cand)

    assert ice_agent.gathering_state == :complete

    # make ice_agent connected
    ice_agent = connect(ice_agent)

    # replace candidate with the mock one
    [local_cand] = Map.values(ice_agent.local_cands)
    mock_cand = %Candidate.Mock{base: local_cand.base}
    ice_agent = %{ice_agent | local_cands: %{mock_cand.base.id => mock_cand}}

    # try to send some data
    ice_agent = ICEAgent.send_data(ice_agent, "somedata")

    # assert that the local candidate hasn't been closed and that the agent hasn't moved to a failed state
    assert [%{base: %{closed?: false}}] = Map.values(ice_agent.local_cands)
    assert ice_agent.state == :connected

    # assert that the local candidate's state was updated after the packet was discarded
    assert [
             %{
               state: :succeeded,
               packets_discarded_on_send: 1,
               bytes_discarded_on_send: 8
             }
           ] = Map.values(ice_agent.checklist)
  end

  test "relay connection" do
    remote_cand_ip = @remote_cand.address
    remote_cand_port = @remote_cand.port

    ice_agent =
      ICEAgent.new(
        controlling_process: self(),
        role: :controlling,
        if_discovery_module: IfDiscovery.Mock,
        transport_module: Transport.Mock,
        ice_servers: [
          %{
            urls: "turn:#{@turn_ip_str}:#{@turn_port}?transport=udp",
            username: @turn_username,
            credential: @turn_password
          }
        ],
        ice_transport_policy: :relay
      )
      |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
      |> ICEAgent.gather_candidates()
      |> ICEAgent.add_remote_candidate(@remote_cand)

    [socket] = ice_agent.sockets

    # create relay candidate
    ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
    req = read_allocate_request(socket)
    resp = allocate_error_response(req.transaction_id)
    ice_agent = ICEAgent.handle_udp(ice_agent, socket, @turn_ip, @turn_port, resp)
    req = read_allocate_request(socket)
    resp = allocate_success_response(req.transaction_id, ice_agent.transport_module, socket)
    ice_agent = ICEAgent.handle_udp(ice_agent, socket, @turn_ip, @turn_port, resp)

    # assert there is a new relay candidate
    assert %ExICE.Priv.Candidate.Relay{} =
             ice_agent.local_cands
             |> Map.values()
             |> Enum.find(&(&1.base.type == :relay))

    # assert client sends create permission request
    ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
    assert packet = Transport.Mock.recv(socket)
    assert {:ok, req} = ExSTUN.Message.decode(packet)
    assert req.type.class == :request
    assert req.type.method == :create_permission

    # send success response
    resp =
      Message.new(
        req.transaction_id,
        %Type{class: :success_response, method: :create_permission},
        []
      )
      |> Message.with_integrity(Message.lt_key(@turn_username, @turn_password, @turn_realm))
      |> Message.encode()

    ice_agent = ICEAgent.handle_udp(ice_agent, socket, @turn_ip, @turn_port, resp)

    # assert client sends ice binding request and channel bind request
    assert packet = Transport.Mock.recv(socket)
    assert {:ok, req} = ExSTUN.Message.decode(packet)
    assert req.type.class == :indication
    assert req.type.method == :send

    {:ok, %Data{value: data}} = Message.get_attribute(req, Data)
    {:ok, req} = ExSTUN.Message.decode(data)
    assert req.type.class == :request
    assert req.type.method == :binding

    assert packet = Transport.Mock.recv(socket)
    assert {:ok, channel_req} = ExSTUN.Message.decode(packet)
    assert channel_req.type.class == :request
    assert channel_req.type.method == :channel_bind

    # send binding success response
    resp =
      Message.new(req.transaction_id, %Type{class: :success_response, method: :binding}, [
        %XORMappedAddress{address: @turn_relay_ip, port: @turn_relay_port}
      ])
      |> Message.with_integrity(ice_agent.remote_pwd)
      |> Message.with_fingerprint()
      |> Message.encode()

    resp =
      Message.new(%Type{class: :indication, method: :data}, [
        %Data{value: resp},
        %XORPeerAddress{address: remote_cand_ip, port: remote_cand_port}
      ])
      |> Message.encode()

    ice_agent = ICEAgent.handle_udp(ice_agent, socket, @turn_ip, @turn_port, resp)

    # assert there is one succeeded pair
    assert [%CandidatePair{state: :succeeded}] = Map.values(ice_agent.checklist)

    # try to send some data
    ice_agent = ICEAgent.send_data(ice_agent, "somedata")

    # assert data has been sent
    assert packet = Transport.Mock.recv(socket)
    assert {:ok, indication} = ExSTUN.Message.decode(packet)
    assert indication.type.class == :indication
    assert indication.type.method == :send

    {:ok, %Data{value: "somedata"}} = Message.get_attribute(indication, Data)

    # try to receive some data
    indication =
      Message.new(%Type{class: :indication, method: :data}, [
        %Data{value: "someremotedata"},
        %XORPeerAddress{address: remote_cand_ip, port: remote_cand_port}
      ])
      |> Message.encode()

    ice_agent = ICEAgent.handle_udp(ice_agent, socket, @turn_ip, @turn_port, indication)
    assert_receive {:ex_ice, _pid, {:data, "someremotedata"}}

    # send channel bind success response
    channel_resp =
      Message.new(
        channel_req.transaction_id,
        %Type{class: :success_response, method: :channel_bind},
        []
      )
      |> Message.with_integrity(Message.lt_key(@turn_username, @turn_password, @turn_realm))
      |> Message.encode()

    ice_agent = ICEAgent.handle_udp(ice_agent, socket, @turn_ip, @turn_port, channel_resp)

    # try to once again send some data, this time it should be sent over channel
    _ice_agent = ICEAgent.send_data(ice_agent, "somedata")
    assert packet = Transport.Mock.recv(socket)
    assert nil == Transport.Mock.recv(socket)
    assert ExTURN.channel_data?(packet)
    assert <<_channel_number::16, _len::16, "somedata">> = packet
  end

  defp connect(ice_agent) do
    [socket] = ice_agent.sockets
    [remote_cand] = Map.values(ice_agent.remote_cands)

    ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
    req = read_binding_request(socket, ice_agent.remote_pwd)

    resp =
      binding_response(
        req.transaction_id,
        ice_agent.transport_module,
        socket,
        ice_agent.remote_pwd
      )

    ice_agent =
      ICEAgent.handle_udp(
        ice_agent,
        socket,
        remote_cand.address,
        remote_cand.port,
        resp
      )

    assert [%CandidatePair{state: :succeeded}] = Map.values(ice_agent.checklist)
    assert ice_agent.state == :connected
    ice_agent
  end

  defp binding_indication() do
    Message.new(%Type{class: :indication, method: :binding}) |> Message.encode()
  end

  defp binding_request(role, tiebreaker, local_ufrag, remote_ufrag, remote_pwd, opts \\ []) do
    ice_attrs =
      if role == :controlled do
        [%ICEControlling{tiebreaker: tiebreaker + 1}, %UseCandidate{}]
      else
        [%ICEControlled{tiebreaker: tiebreaker - 1}]
      end

    attrs =
      [
        %Username{value: "#{remote_ufrag}:#{local_ufrag}"},
        %Priority{priority: opts[:priority] || 1234}
      ] ++ ice_attrs

    request =
      Message.new(%Type{class: :request, method: :binding}, attrs)
      |> Message.with_integrity(remote_pwd)
      |> Message.with_fingerprint()

    Message.encode(request)
  end

  defp binding_response(t_id, transport_module, socket, remote_pwd) do
    {:ok, {sock_ip, sock_port}} = transport_module.sockname(socket)

    Message.new(t_id, %Type{class: :success_response, method: :binding}, [
      %XORMappedAddress{address: sock_ip, port: sock_port}
    ])
    |> Message.with_integrity(remote_pwd)
    |> Message.with_fingerprint()
    |> Message.encode()
  end

  defp allocate_error_response(t_id) do
    Message.new(t_id, %Type{class: :error_response, method: :allocate}, [
      %Realm{value: @turn_realm},
      %Nonce{value: @turn_nonce},
      %ErrorCode{code: 401}
    ])
    |> Message.encode()
  end

  defp allocate_success_response(t_id, transport_module, socket) do
    {:ok, {sock_ip, sock_port}} = transport_module.sockname(socket)

    Message.new(t_id, %Type{class: :success_response, method: :allocate}, [
      %XORRelayedAddress{address: @turn_relay_ip, port: @turn_relay_port},
      %Lifetime{value: 600},
      %XORMappedAddress{address: sock_ip, port: sock_port}
    ])
    |> Message.with_integrity(Message.lt_key(@turn_username, @turn_password, @turn_realm))
    |> Message.encode()
  end

  defp read_allocate_request(socket) do
    assert packet = Transport.Mock.recv(socket)
    assert {:ok, req} = ExSTUN.Message.decode(packet)
    assert req.type.class == :request
    assert req.type.method == :allocate
    req
  end
end
