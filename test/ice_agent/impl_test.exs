defmodule ExICE.ICEAgent.ImplTest do
  use ExUnit.Case, async: true

  alias ExICE.{Candidate, IfDiscovery, ICEAgent}
  alias ExICE.Attribute.{ICEControlled, Priority}
  alias ExICE.Support.Transport

  alias ExSTUN.Message
  alias ExSTUN.Message.Type
  alias ExSTUN.Message.Attribute.{ErrorCode, Username, XORMappedAddress}

  defmodule IfDiscovery.Mock do
    @behaviour ExICE.IfDiscovery

    @impl true
    def getifaddrs() do
      ifs = [{~c"mockif", [{:flags, [:up, :running]}, {:addr, {192, 168, 0, 1}}]}]
      {:ok, ifs}
    end
  end

  describe "binding request" do
    setup do
      ice_agent =
        ICEAgent.Impl.new(
          controlling_process: self(),
          role: :controlling,
          if_discovery_module: IfDiscovery.Mock,
          transport_module: Transport.Mock
        )

      ice_agent = ICEAgent.Impl.gather_candidates(ice_agent)

      remote_cand = Candidate.new(:host, {192, 168, 0, 1}, 8445, nil, nil, nil)

      %{ice_agent: ice_agent, remote_cand: remote_cand}
    end

    test "with correct attributes", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [local_cand] = ice_agent.local_cands

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
        ICEAgent.Impl.handle_udp(
          ice_agent,
          local_cand.socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert [{_socket, packet}] = :ets.lookup(:transport_mock, local_cand.socket)
      assert {:ok, msg} = ExSTUN.Message.decode(packet)
      assert msg.type == %ExSTUN.Message.Type{class: :success_response, method: :binding}
      assert msg.transaction_id == request.transaction_id
      assert length(msg.attributes) == 3

      assert {:ok, %XORMappedAddress{address: {192, 168, 0, 1}, port: 8445}} =
               ExSTUN.Message.get_attribute(msg, XORMappedAddress)

      assert :ok == ExSTUN.Message.check_fingerprint(msg)
      assert {:ok, _key} = ExSTUN.Message.authenticate_st(msg, ice_agent.local_pwd)
    end

    test "without username", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [local_cand] = ice_agent.local_cands

      request =
        Message.new(%Type{class: :request, method: :binding}, [
          %Priority{priority: 1234},
          %ICEControlled{tiebreaker: 1234}
        ])
        |> Message.with_integrity(ice_agent.local_pwd)
        |> Message.with_fingerprint()

      raw_request = Message.encode(request)

      _ice_agent =
        ICEAgent.Impl.handle_udp(
          ice_agent,
          local_cand.socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert_bad_request_error_response(local_cand.socket, request)
    end

    test "without message-integrity", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [local_cand] = ice_agent.local_cands

      request =
        Message.new(%Type{class: :request, method: :binding}, [
          %Username{value: "#{ice_agent.local_ufrag}:someufrag"},
          %Priority{priority: 1234},
          %ICEControlled{tiebreaker: 1234}
        ])
        |> Message.with_fingerprint()

      raw_request = Message.encode(request)

      _ice_agent =
        ICEAgent.Impl.handle_udp(
          ice_agent,
          local_cand.socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert_bad_request_error_response(local_cand.socket, request)
    end

    test "without fingerprint", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [local_cand] = ice_agent.local_cands

      request =
        Message.new(%Type{class: :request, method: :binding}, [
          %Username{value: "#{ice_agent.local_ufrag}:someufrag"},
          %Priority{priority: 1234},
          %ICEControlled{tiebreaker: 1234}
        ])
        |> Message.with_integrity(ice_agent.local_pwd)

      raw_request = Message.encode(request)

      _ice_agent =
        ICEAgent.Impl.handle_udp(
          ice_agent,
          local_cand.socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert_silently_discarded(local_cand.socket)
    end

    test "without role", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [local_cand] = ice_agent.local_cands

      request =
        Message.new(%Type{class: :request, method: :binding}, [
          %Username{value: "#{ice_agent.local_ufrag}:someufrag"},
          %Priority{priority: 1234}
        ])
        |> Message.with_integrity(ice_agent.local_pwd)
        |> Message.with_fingerprint()

      raw_request = Message.encode(request)

      _ice_agent =
        ICEAgent.Impl.handle_udp(
          ice_agent,
          local_cand.socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert_bad_request_error_response(local_cand.socket, request)
    end

    test "without priority", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [local_cand] = ice_agent.local_cands

      request =
        Message.new(%Type{class: :request, method: :binding}, [
          %Username{value: "#{ice_agent.local_ufrag}:someufrag"},
          %ICEControlled{tiebreaker: 1234}
        ])
        |> Message.with_integrity(ice_agent.local_pwd)
        |> Message.with_fingerprint()

      raw_request = Message.encode(request)

      _ice_agent =
        ICEAgent.Impl.handle_udp(
          ice_agent,
          local_cand.socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert_bad_request_error_response(local_cand.socket, request)
    end

    test "with non-matching username", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [local_cand] = ice_agent.local_cands

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
        ICEAgent.Impl.handle_udp(
          ice_agent,
          local_cand.socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert_unauthenticated_error_response(local_cand.socket, request)
    end

    test "with non-matching fingerprint", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [local_cand] = ice_agent.local_cands

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
        ICEAgent.Impl.handle_udp(
          ice_agent,
          local_cand.socket,
          remote_cand.address,
          remote_cand.port,
          request
        )

      assert_silently_discarded(local_cand.socket)
    end

    test "with non-matching message integrity", %{ice_agent: ice_agent, remote_cand: remote_cand} do
      [local_cand] = ice_agent.local_cands

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
        ICEAgent.Impl.handle_udp(
          ice_agent,
          local_cand.socket,
          remote_cand.address,
          remote_cand.port,
          raw_request
        )

      assert_unauthenticated_error_response(local_cand.socket, request)
    end

    defp assert_bad_request_error_response(socket, request) do
      assert [{_socket, packet}] = :ets.lookup(:transport_mock, socket)
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
      assert [{_socket, packet}] = :ets.lookup(:transport_mock, socket)
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
      assert [{_socket, nil}] = :ets.lookup(:transport_mock, socket)
    end
  end

  test "gather srflx candidates" do
    ice_agent =
      ICEAgent.Impl.new(
        controlling_process: self(),
        role: :controlling,
        transport_module: Transport.Mock,
        if_discovery_module: IfDiscovery.Mock,
        stun_servers: ["stun:192.168.0.3:19302"]
      )

    ice_agent = ICEAgent.Impl.set_remote_credentials(ice_agent, "someufrag", "somepwd")
    ice_agent = ICEAgent.Impl.gather_candidates(ice_agent)
    [local_cand] = ice_agent.local_cands

    # assert no transactions are started until handle_timeout is called
    assert [{_socket, nil}] = :ets.lookup(:transport_mock, local_cand.socket)

    ice_agent = ICEAgent.Impl.handle_timeout(ice_agent)

    assert [{_socket, packet}] = :ets.lookup(:transport_mock, local_cand.socket)
    assert {:ok, req} = ExSTUN.Message.decode(packet)

    resp =
      Message.new(req.transaction_id, %Type{class: :success_response, method: :binding}, [
        %XORMappedAddress{address: {192, 168, 0, 2}, port: local_cand.port + 1}
      ])
      |> Message.encode()

    ice_agent =
      ICEAgent.Impl.handle_udp(ice_agent, local_cand.socket, {192, 168, 0, 3}, 19_302, resp)

    assert [srflx_cand | _cands] = ice_agent.local_cands
    assert srflx_cand.type == :srflx
    assert srflx_cand.address == {192, 168, 0, 2}
    assert srflx_cand.port == local_cand.port + 1

    assert ice_agent.gathering_transactions[req.transaction_id].state == :complete
  end
end
