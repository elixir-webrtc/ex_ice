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

      %{ice_agent: ice_agent}
    end

    test "with correct remote candidate", %{ice_agent: ice_agent} do
      remote_cand = ExICE.Candidate.new(:host, address: {192, 168, 0, 2}, port: 8445)
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, remote_cand)

      assert [%ExICE.Candidate{} = r_cand] = Map.values(ice_agent.remote_cands)
      # override id for the purpose of comparison
      r_cand = %ExICE.Candidate{r_cand | id: remote_cand.id}
      assert r_cand == remote_cand
    end

    test "with duplicated remote candidate", %{ice_agent: ice_agent} do
      remote_cand = ExICE.Candidate.new(:host, address: {192, 168, 0, 2}, port: 8445)
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, remote_cand)
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, remote_cand)
      assert map_size(ice_agent.remote_cands) == 1
    end

    test "without remote credentials", %{ice_agent: ice_agent} do
      ice_agent = %{ice_agent | remote_ufrag: nil, remote_pwd: nil}
      remote_cand = ExICE.Candidate.new(:host, address: {192, 168, 0, 2}, port: 8445)
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, remote_cand)
      assert %{} == ice_agent.remote_cands
    end

    test "after setting end-of-candidates", %{ice_agent: ice_agent} do
      remote_cand = ExICE.Candidate.new(:host, address: {192, 168, 0, 2}, port: 8445)
      ice_agent = ICEAgent.end_of_candidates(ice_agent)
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, remote_cand)
      assert %{} == ice_agent.remote_cands
    end
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
        transport_module: ice_agent.transport_module,
        socket: socket
      )

    local_cands = %{host_cand.base.id => host_cand, srflx_cand.base.id => srflx_cand}
    ice_agent = %{ice_agent | local_cands: local_cands}

    remote_cand = ExICE.Candidate.new(:host, address: {192, 168, 0, 3}, port: 8445)

    ice_agent = ICEAgent.add_remote_candidate(ice_agent, remote_cand)

    # assert there is only one pair with host local candidate
    assert [pair] = Map.values(ice_agent.checklist)
    assert pair.local_cand_id == host_cand.base.id
  end

  test "forwards data received on a faild pair and re-schedules" do
    remote_cand = ExICE.Candidate.new(:host, address: {192, 168, 0, 3}, port: 8445)

    ice_agent =
      ICEAgent.new(
        controlling_process: self(),
        role: :controlling,
        transport_module: Transport.Mock,
        if_discovery_module: IfDiscovery.Mock
      )
      |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
      |> ICEAgent.gather_candidates()
      |> ICEAgent.add_remote_candidate(remote_cand)

    [socket] = ice_agent.sockets

    # mark pair as failed
    [pair] = Map.values(ice_agent.checklist)
    ice_agent = put_in(ice_agent.checklist[pair.id], %{pair | state: :failed})

    # clear ta_timer, ignore outgoing binding request that has been generated
    ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
    assert ice_agent.ta_timer == nil

    # feed some data
    ice_agent =
      ICEAgent.handle_udp(ice_agent, socket, remote_cand.address, remote_cand.port, "some data")

    # assert that data has been passed
    assert_receive {:ex_ice, _pid, {:data, "some data"}}

    # assert that pair is re-scheduled
    assert [pair] = Map.values(ice_agent.checklist)
    assert pair.state == :waiting
    assert ice_agent.ta_timer != nil
  end

  describe "re-schedules failed pair on incoming binding request" do
    test "with controlling ice agent" do
      remote_cand = ExICE.Candidate.new(:host, address: {192, 168, 0, 3}, port: 8445)

      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlling,
          transport_module: Transport.Mock,
          if_discovery_module: IfDiscovery.Mock
        )
        |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
        |> ICEAgent.gather_candidates()
        |> ICEAgent.add_remote_candidate(remote_cand)

      test_rescheduling(ice_agent, remote_cand)
    end

    test "with controlled ice agent" do
      remote_cand = ExICE.Candidate.new(:host, address: {192, 168, 0, 3}, port: 8445)

      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlled,
          transport_module: Transport.Mock,
          if_discovery_module: IfDiscovery.Mock
        )
        |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
        |> ICEAgent.gather_candidates()
        |> ICEAgent.add_remote_candidate(remote_cand)

      test_rescheduling(ice_agent, remote_cand)
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
      remote_cand = ExICE.Candidate.new(:host, address: {192, 168, 0, 2}, port: 8445)

      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlling,
          if_discovery_module: IfDiscovery.Mock,
          transport_module: Transport.Mock
        )
        |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
        |> ICEAgent.gather_candidates()
        |> ICEAgent.add_remote_candidate(remote_cand)

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
    end

    test "timeout on unconnected pair", %{ice_agent: ice_agent} do
      [socket] = ice_agent.sockets
      [pair] = Map.values(ice_agent.checklist)
      ICEAgent.handle_keepalive_timeout(ice_agent, pair.id)

      assert nil == Transport.Mock.recv(socket)
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

      remote_cand = ExICE.Candidate.new(:host, address: {192, 168, 0, 2}, port: 8445)

      %{ice_agent: ice_agent, remote_cand: remote_cand}
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
      remote_cand = ExICE.Candidate.new(:host, address: {192, 168, 0, 2}, port: 8445)

      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlling,
          if_discovery_module: IfDiscovery.Mock,
          transport_module: Transport.Mock
        )
        |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
        |> ICEAgent.gather_candidates()
        |> ICEAgent.add_remote_candidate(remote_cand)

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

  describe "connectivity check" do
    setup do
      remote_cand = ExICE.Candidate.new(:host, address: {192, 168, 0, 2}, port: 8445)

      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlling,
          if_discovery_module: IfDiscovery.Mock,
          transport_module: Transport.Mock
        )
        |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
        |> ICEAgent.gather_candidates()
        |> ICEAgent.add_remote_candidate(remote_cand)

      %{ice_agent: ice_agent, remote_cand: remote_cand}
    end

    test "request", %{ice_agent: ice_agent} do
      [socket] = ice_agent.sockets

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

      assert [%CandidatePair{state: :in_progress}] = Map.values(ice_agent.checklist)
    end

    test "success response", %{ice_agent: ice_agent, remote_cand: remote_cand} do
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
        ICEAgent.handle_udp(
          ice_agent,
          socket,
          remote_cand.address,
          remote_cand.port,
          resp
        )

      assert [%CandidatePair{state: :succeeded}] = Map.values(ice_agent.checklist)
    end

    test "success response with non-matching message integrity", %{
      ice_agent: ice_agent,
      remote_cand: remote_cand
    } do
      [socket] = ice_agent.sockets

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
      # Hence, no impact on pair's state.
      assert [%CandidatePair{state: :in_progress}] = Map.values(ice_agent.checklist)
    end

    test "bad request error response", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [socket] = ice_agent.sockets

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

      assert [%CandidatePair{state: :failed}] = Map.values(ice_agent.checklist)
    end

    test "unauthenticated error response", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [socket] = ice_agent.sockets

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

      assert [%CandidatePair{state: :failed}] = Map.values(ice_agent.checklist)
    end

    test "response from non-symmetric address", %{ice_agent: ice_agent, remote_cand: remote_cand} do
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
    end

    defp read_binding_request(socket, remote_pwd) do
      packet = Transport.Mock.recv(socket)
      {:ok, req} = ExSTUN.Message.decode(packet)
      :ok = ExSTUN.Message.authenticate(req, remote_pwd)
      req
    end
  end

  describe "connectivity check rtx" do
    setup do
      remote_cand = ExICE.Candidate.new(:host, address: {192, 168, 0, 2}, port: 8445)

      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlling,
          if_discovery_module: IfDiscovery.Mock,
          transport_module: Transport.Mock
        )
        |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
        |> ICEAgent.gather_candidates()
        |> ICEAgent.add_remote_candidate(remote_cand)

      %{ice_agent: ice_agent, remote_cand: remote_cand}
    end

    test "retransmits cc when there is no response", %{
      ice_agent: ice_agent,
      remote_cand: remote_cand
    } do
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
    remote_cand = ExICE.Candidate.new(:host, address: {192, 168, 0, 2}, port: 8445)

    ice_agent =
      ICEAgent.new(
        controlling_process: self(),
        role: :controlling,
        if_discovery_module: IfDiscovery.Mock,
        transport_module: Transport.Mock
      )
      |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
      |> ICEAgent.gather_candidates()
      |> ICEAgent.add_remote_candidate(remote_cand)

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

  test "cleans up agent state when the connection fails" do
    remote_cand = ExICE.Candidate.new(:host, address: {192, 168, 0, 3}, port: 8445)

    ice_agent =
      ICEAgent.new(
        controlling_process: self(),
        role: :controlling,
        transport_module: Transport.Mock,
        if_discovery_module: IfDiscovery.Mock
      )
      |> ICEAgent.set_remote_credentials("remoteufrag", "remotepwd")
      |> ICEAgent.gather_candidates()
      |> ICEAgent.add_remote_candidate(remote_cand)

    # save creds as they will be cleared after moving to the failed state
    local_ufrag = ice_agent.local_ufrag
    local_pwd = ice_agent.local_pwd

    [socket] = ice_agent.sockets

    # mark pair as failed
    [pair] = Map.values(ice_agent.checklist)
    ice_agent = put_in(ice_agent.checklist[pair.id], %{pair | state: :failed})

    # set eoc flag
    ice_agent = ICEAgent.end_of_candidates(ice_agent)

    # agent should have moved to the failed state
    assert ice_agent.state == :failed
    assert ice_agent.sockets == []
    assert ice_agent.local_cands == %{}
    assert ice_agent.remote_cands == %{}
    assert ice_agent.gathering_transactions == %{}
    assert ice_agent.selected_pair_id == nil
    assert ice_agent.conn_checks == %{}
    assert ice_agent.checklist == %{}
    assert ice_agent.local_ufrag == nil
    assert ice_agent.local_pwd == nil
    assert ice_agent.remote_ufrag == nil
    assert ice_agent.remote_pwd == nil
    assert ice_agent.eoc == false
    assert ice_agent.nominating? == {false, nil}

    # assert that handle_udp ignores incoming data i.e. the state of ice agent didn't change
    new_ice_agent =
      ICEAgent.handle_udp(ice_agent, socket, remote_cand.address, remote_cand.port, "some data")

    assert ice_agent == new_ice_agent

    # the same with incoming binding request
    req =
      binding_request(
        ice_agent.role,
        ice_agent.tiebreaker,
        "remoteufrag",
        local_ufrag,
        local_pwd
      )

    new_ice_agent =
      ICEAgent.handle_udp(ice_agent, socket, remote_cand.address, remote_cand.port, req)

    assert ice_agent == new_ice_agent

    # and handle_ta_timeout
    new_ice_agent = ICEAgent.handle_ta_timeout(ice_agent)
    assert ice_agent == new_ice_agent
  end

  test "cleans up agent state when the connection completes" do
    r_cand1 = ExICE.Candidate.new(:host, address: {192, 168, 0, 3}, port: 8445)
    r_cand2 = ExICE.Candidate.new(:srflx, address: {192, 168, 0, 4}, port: 8445)

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

    # assert we have two succeeded pairs
    assert [%{state: :succeeded}, %{state: :succeeded}] = Map.values(ice_agent.checklist)

    {_id, srflx_pair} =
      Enum.find(ice_agent.checklist, fn {_pair_id, pair} -> pair.remote_cand_id == r_cand2.id end)

    assert :connected == ice_agent.state

    # set end-of-candidates
    ice_agent = ICEAgent.end_of_candidates(ice_agent)

    # assert ice agent changed its state to completed
    # and we have one pair and one remote cand
    assert ice_agent.state == :completed
    assert [%{state: :succeeded}] = Map.values(ice_agent.checklist)
    assert [%{type: :host}] = Map.values(ice_agent.remote_cands)

    # try to feed data from the srflx remote cand
    new_ice_agent =
      ICEAgent.handle_udp(ice_agent, socket, r_cand2.address, r_cand2.port, "some data")

    assert ice_agent == new_ice_agent

    # try to handle keepalive on the srflx pair
    new_ice_agent = ICEAgent.handle_keepalive_timeout(ice_agent, srflx_pair.id)
    assert ice_agent == new_ice_agent
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
    # 3. assert that after unsuccessful data sending, ice_agent moves to the failed state
    # as there are no other pairs
    remote_cand = ExICE.Candidate.new(:host, address: {192, 168, 0, 2}, port: 8445)

    ice_agent =
      ICEAgent.new(
        controlling_process: self(),
        role: :controlling,
        if_discovery_module: IfDiscovery.Mock,
        transport_module: Transport.Mock
      )
      |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
      |> ICEAgent.gather_candidates()
      |> ICEAgent.add_remote_candidate(remote_cand)

    assert ice_agent.gathering_state == :complete

    # make ice_agent connected
    ice_agent = connect(ice_agent)

    # replace candidate with the mock one
    [local_cand] = Map.values(ice_agent.local_cands)
    mock_cand = %Candidate.Mock{base: local_cand.base}
    ice_agent = %{ice_agent | local_cands: %{mock_cand.base.id => mock_cand}}

    # try to send some data
    ice_agent = ICEAgent.send_data(ice_agent, "somedata")

    # assert that ice_agent removed failed candidate and moved to the failed state
    assert ice_agent.local_cands == %{}
    assert ice_agent.state == :failed
    assert ice_agent.checklist == %{}
  end

  test "relay connection" do
    remote_cand_ip = {192, 168, 0, 2}
    remote_cand_port = 8445
    remote_cand = ExICE.Candidate.new(:host, address: remote_cand_ip, port: remote_cand_port)

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
      |> ICEAgent.add_remote_candidate(remote_cand)

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

  defp binding_request(role, tiebreaker, local_ufrag, remote_ufrag, remote_pwd) do
    ice_attrs =
      if role == :controlled do
        [%ICEControlling{tiebreaker: tiebreaker + 1}, %UseCandidate{}]
      else
        [%ICEControlled{tiebreaker: tiebreaker - 1}]
      end

    attrs =
      [
        %Username{value: "#{remote_ufrag}:#{local_ufrag}"},
        %Priority{priority: 1234}
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
