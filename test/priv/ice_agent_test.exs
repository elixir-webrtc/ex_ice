defmodule ExICE.Priv.ICEAgentTest do
  use ExUnit.Case, async: true

  alias ExICE.Priv.{Candidate, CandidatePair, IfDiscovery, ICEAgent}
  alias ExICE.Priv.Attribute.{ICEControlled, ICEControlling, Priority}
  alias ExICE.Support.Transport

  alias ExSTUN.Message
  alias ExSTUN.Message.Type
  alias ExSTUN.Message.Attribute.{ErrorCode, Username, XORMappedAddress}

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

  describe "add_remote_candidate/2" do
    setup do
      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlling,
          if_discovery_module: IfDiscovery.Mock,
          transport_module: Transport.Mock
        )

      %{ice_agent: ice_agent}
    end

    test "with correct remote candidate", %{ice_agent: ice_agent} do
      remote_cand = ExICE.Candidate.new(:host, address: {192, 168, 0, 2}, port: 8445)
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, ExICE.Candidate.marshal(remote_cand))

      assert [%ExICE.Candidate{} = r_cand] = Map.values(ice_agent.remote_cands)
      # override id for the purpose of comparision
      r_cand = %ExICE.Candidate{r_cand | id: remote_cand.id}
      assert r_cand == remote_cand
    end

    test "with invalid remote candidate", %{ice_agent: ice_agent} do
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, "some invalid candidate string")
      assert %{} == ice_agent.remote_cands
    end

    test "with invalid mdns remote candidate", %{ice_agent: ice_agent} do
      remote_cand =
        ExICE.Candidate.new(:host, address: "somehopefullyinvalidmdnscandidate.local", port: 8445)

      ice_agent = ICEAgent.add_remote_candidate(ice_agent, ExICE.Candidate.marshal(remote_cand))
      assert %{} == ice_agent.remote_cands
    end

    test "after setting end-of-candidates", %{ice_agent: ice_agent} do
      remote_cand = ExICE.Candidate.new(:host, address: {192, 168, 0, 2}, port: 8445)
      ice_agent = ICEAgent.end_of_candidates(ice_agent)
      ice_agent = ICEAgent.add_remote_candidate(ice_agent, ExICE.Candidate.marshal(remote_cand))
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
      [local_cand] = Map.values(ice_agent.local_cands)

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
          local_cand.base.socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert packet = Transport.Mock.recv(local_cand.base.socket)
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
      [local_cand] = Map.values(ice_agent.local_cands)

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
          local_cand.base.socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert_bad_request_error_response(local_cand.base.socket, request)
    end

    test "without message-integrity", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [local_cand] = Map.values(ice_agent.local_cands)

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
          local_cand.base.socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert_bad_request_error_response(local_cand.base.socket, request)
    end

    test "without fingerprint", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [local_cand] = Map.values(ice_agent.local_cands)

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
          local_cand.base.socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert_silently_discarded(local_cand.base.socket)
    end

    test "without role", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [local_cand] = Map.values(ice_agent.local_cands)

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
          local_cand.base.socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert_bad_request_error_response(local_cand.base.socket, request)
    end

    test "without priority", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [local_cand] = Map.values(ice_agent.local_cands)

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
          local_cand.base.socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert_bad_request_error_response(local_cand.base.socket, request)
    end

    test "with non-matching username", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [local_cand] = Map.values(ice_agent.local_cands)

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
          local_cand.base.socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert_unauthenticated_error_response(local_cand.base.socket, request)
    end

    test "with non-matching fingerprint", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [local_cand] = Map.values(ice_agent.local_cands)

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
          local_cand.base.socket,
          remote_cand.address,
          remote_cand.port,
          request
        )

      assert_silently_discarded(local_cand.base.socket)
    end

    test "with non-matching message integrity", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [local_cand] = Map.values(ice_agent.local_cands)

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
          local_cand.base.socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert_unauthenticated_error_response(local_cand.base.socket, request)
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
        |> ICEAgent.add_remote_candidate(ExICE.Candidate.marshal(remote_cand))

      %{ice_agent: ice_agent, remote_cand: remote_cand}
    end

    test "request", %{ice_agent: ice_agent} do
      [local_cand] = Map.values(ice_agent.local_cands)

      ice_agent = ICEAgent.handle_timeout(ice_agent)

      assert packet = Transport.Mock.recv(local_cand.base.socket)
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
      [local_cand] = Map.values(ice_agent.local_cands)

      ice_agent = ICEAgent.handle_timeout(ice_agent)

      req = read_binding_request(local_cand.base.socket, ice_agent.remote_pwd)
      resp = binding_response(req.transaction_id, local_cand, ice_agent.remote_pwd)

      ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          local_cand.base.socket,
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
      [local_cand] = Map.values(ice_agent.local_cands)

      ice_agent = ICEAgent.handle_timeout(ice_agent)

      <<first_byte, rest::binary>> = ice_agent.remote_pwd
      invalid_remote_pwd = <<first_byte + 1, rest::binary>>

      req = read_binding_request(local_cand.base.socket, ice_agent.remote_pwd)
      resp = binding_response(req.transaction_id, local_cand, invalid_remote_pwd)

      ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          local_cand.base.socket,
          remote_cand.address,
          remote_cand.port,
          resp
        )

      # Unauthenticated response is ignored as it was never received.
      # Hence, no impact on pair's state.
      assert [%CandidatePair{state: :in_progress}] = Map.values(ice_agent.checklist)
    end

    test "bad request error response", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [local_cand] = Map.values(ice_agent.local_cands)

      ice_agent = ICEAgent.handle_timeout(ice_agent)

      req = read_binding_request(local_cand.base.socket, ice_agent.remote_pwd)

      resp =
        Message.new(req.transaction_id, %Type{class: :error_response, method: :binding}, [
          %ErrorCode{code: 400}
        ])
        |> Message.with_fingerprint()
        |> Message.encode()

      ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          local_cand.base.socket,
          remote_cand.address,
          remote_cand.port,
          resp
        )

      assert [%CandidatePair{state: :failed}] = Map.values(ice_agent.checklist)
    end

    test "unauthenticated error response", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [local_cand] = Map.values(ice_agent.local_cands)

      ice_agent = ICEAgent.handle_timeout(ice_agent)

      req = read_binding_request(local_cand.base.socket, ice_agent.remote_pwd)

      resp =
        Message.new(req.transaction_id, %Type{class: :error_response, method: :binding}, [
          %ErrorCode{code: 401}
        ])
        |> Message.with_fingerprint()
        |> Message.encode()

      ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          local_cand.base.socket,
          remote_cand.address,
          remote_cand.port,
          resp
        )

      assert [%CandidatePair{state: :failed}] = Map.values(ice_agent.checklist)
    end

    test "response from non-symmetric address", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [local_cand] = Map.values(ice_agent.local_cands)

      ice_agent = ICEAgent.handle_timeout(ice_agent)

      req = read_binding_request(local_cand.base.socket, ice_agent.remote_pwd)
      resp = binding_response(req.transaction_id, local_cand, ice_agent.remote_pwd)

      {a, b, c, d} = remote_cand.address

      ice_agent =
        ICEAgent.handle_udp(
          ice_agent,
          local_cand.base.socket,
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

  describe "gather srflx candidates" do
    setup do
      ice_agent =
        ICEAgent.new(
          controlling_process: self(),
          role: :controlling,
          transport_module: Transport.Mock,
          if_discovery_module: IfDiscovery.Mock,
          ice_servers: [%{url: "stun:192.168.0.3:19302"}]
        )
        |> ICEAgent.set_remote_credentials("someufrag", "somepwd")
        |> ICEAgent.gather_candidates()

      [local_cand] = Map.values(ice_agent.local_cands)

      # assert no transactions are started until handle_timeout is called
      assert nil == Transport.Mock.recv(local_cand.base.socket)

      %{ice_agent: ice_agent}
    end

    test "success response", %{ice_agent: ice_agent} do
      [local_cand] = Map.values(ice_agent.local_cands)

      ice_agent = ICEAgent.handle_timeout(ice_agent)

      assert packet = Transport.Mock.recv(local_cand.base.socket)
      assert {:ok, req} = ExSTUN.Message.decode(packet)

      resp =
        Message.new(req.transaction_id, %Type{class: :success_response, method: :binding}, [
          %XORMappedAddress{address: {192, 168, 0, 2}, port: local_cand.base.port + 1}
        ])
        |> Message.encode()

      ice_agent =
        ICEAgent.handle_udp(ice_agent, local_cand.base.socket, {192, 168, 0, 3}, 19_302, resp)

      # assert there is a new, srflx candidate
      assert %ExICE.Priv.Candidate.Srflx{} =
               srflx_cand =
               ice_agent.local_cands
               |> Map.values()
               |> Enum.find(&(&1.base.type == :srflx))

      assert srflx_cand.base.address == {192, 168, 0, 2}
      assert srflx_cand.base.port == local_cand.base.port + 1
      # assert gathering transaction succeeded
      assert ice_agent.gathering_transactions[req.transaction_id].state == :complete
    end

    test "error response", %{ice_agent: ice_agent} do
      [local_cand] = Map.values(ice_agent.local_cands)

      ice_agent = ICEAgent.handle_timeout(ice_agent)

      assert packet = Transport.Mock.recv(local_cand.base.socket)
      assert {:ok, req} = ExSTUN.Message.decode(packet)

      resp =
        Message.new(req.transaction_id, %Type{class: :error_response, method: :binding}, [
          %ErrorCode{code: 400}
        ])
        |> Message.encode()

      ice_agent =
        ICEAgent.handle_udp(ice_agent, local_cand.base.socket, {192, 168, 0, 3}, 19_302, resp)

      # assert there are no new candidates
      assert [local_cand] == Map.values(ice_agent.local_cands)
      # assert gathering transaction failed
      assert ice_agent.gathering_transactions[req.transaction_id].state == :failed
    end
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
      |> ICEAgent.add_remote_candidate(ExICE.Candidate.marshal(remote_cand))

    [local_cand] = Map.values(ice_agent.local_cands)

    assert ice_agent.gathering_state == :complete

    # make ice_agent connected
    ice_agent = ICEAgent.handle_timeout(ice_agent)
    req = read_binding_request(local_cand.base.socket, ice_agent.remote_pwd)
    resp = binding_response(req.transaction_id, local_cand, ice_agent.remote_pwd)

    ice_agent =
      ICEAgent.handle_udp(
        ice_agent,
        local_cand.base.socket,
        remote_cand.address,
        remote_cand.port,
        resp
      )

    assert [%CandidatePair{state: :succeeded}] = Map.values(ice_agent.checklist)
    assert ice_agent.state == :connected

    # replace candidate with the mock one
    mock_cand = %Candidate.Mock{base: local_cand.base}
    ice_agent = %{ice_agent | local_cands: %{mock_cand.base.id => mock_cand}}

    # try to send some data
    ice_agent = ICEAgent.send_data(ice_agent, "somedata")

    # assert that ice_agent removed failed candidate and moved to the failed state
    assert ice_agent.local_cands == %{}
    assert ice_agent.state == :failed
    assert ice_agent.checklist == %{}
  end

  defp binding_response(t_id, local_cand, remote_pwd) do
    Message.new(t_id, %Type{class: :success_response, method: :binding}, [
      %XORMappedAddress{address: local_cand.base.address, port: local_cand.base.port}
    ])
    |> Message.with_integrity(remote_pwd)
    |> Message.with_fingerprint()
    |> Message.encode()
  end
end
