defmodule ExICE.Priv.ICEAgentTest do
  use ExUnit.Case, async: true

  alias ExICE.Priv.{Candidate, CandidatePair, IfDiscovery, ICEAgent}
  alias ExICE.Priv.Attribute.{ICEControlled, ICEControlling, Priority}
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
      # override id for the purpose of comparision
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
    last_seen = System.monotonic_time(:millisecond) - 5_000
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
      # assert gathering transaction succeeded
      assert ice_agent.gathering_transactions[req.transaction_id].state == :complete
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

      # assert gathering transaction failed
      assert ice_agent.gathering_transactions[req.transaction_id].state == :failed
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

      # assert gathering transaction succeeded
      turn_tr_id = {socket, {@turn_ip, @turn_port}}
      assert ice_agent.gathering_transactions[turn_tr_id].state == :complete
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

      # assert gathering transaction failed
      turn_tr_id = {socket, {@turn_ip, @turn_port}}
      assert ice_agent.gathering_transactions[turn_tr_id].state == :failed
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
      assert ice_agent.gathering_transactions[turn_tr_id].state == :failed
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
