defmodule ExICE.Priv.MDNS.ResolverTest do
  use ExUnit.Case, async: true

  alias ExICE.Support.Transport

  @addr "#{UUID.uuid4()}.local"

  describe "gethostbyname/1" do
    setup do
      assert {:ok, state, {:continue, nil}} = ExICE.Priv.MDNS.Resolver.init(Transport.Mock)
      assert {:noreply, state} = ExICE.Priv.MDNS.Resolver.handle_continue(nil, state)

      assert {:noreply, state} =
               ExICE.Priv.MDNS.Resolver.handle_call(
                 {:gethostbyname, @addr},
                 {self(), make_ref()},
                 state
               )

      assert packet = Transport.Mock.recv(state.socket)
      assert is_binary(packet)
      assert {:ok, msg} = ExICE.Priv.DNS.Message.decode(packet)
      assert msg.qr == false
      assert msg.question == [%{qtype: :a, qclass: :in, qname: @addr, unicast_response: true}]

      on_exit(fn -> Transport.Mock.close(state.socket) end)

      %{state: state}
    end

    test "correct response", %{state: state} do
      response = mdns_response()

      assert {:noreply, _state} =
               ExICE.Priv.MDNS.Resolver.handle_info({:udp, nil, nil, nil, response}, state)

      assert_receive {_ref, {:ok, addr}}
      assert addr == {192, 168, 0, 1}
    end

    test "incorrect response", %{state: state} do
      response =
        %ExICE.Priv.DNS.Message{
          qr: true,
          aa: false,
          answer: [
            %{
              name: @addr,
              type: :a,
              ttl: 120,
              flush_cache: true,
              class: :in,
              rdata: <<192, 168, 0, 1>>
            }
          ]
        }
        |> ExICE.Priv.DNS.Message.encode()

      assert {:noreply, _state} =
               ExICE.Priv.MDNS.Resolver.handle_info({:udp, nil, nil, nil, response}, state)

      refute_received {_ref, {:ok, _addr}}
    end
  end

  test "query rtx" do
    assert {:ok, state, {:continue, nil}} = ExICE.Priv.MDNS.Resolver.init(Transport.Mock)
    assert {:noreply, state} = ExICE.Priv.MDNS.Resolver.handle_continue(nil, state)

    assert {:noreply, state} =
             ExICE.Priv.MDNS.Resolver.handle_call(
               {:gethostbyname, @addr},
               {self(), make_ref()},
               state
             )

    _ = Transport.Mock.recv(state.socket)

    assert {:noreply, state} = ExICE.Priv.MDNS.Resolver.handle_info({:rtx, @addr}, state)
    assert packet = Transport.Mock.recv(state.socket)
    assert is_binary(packet)
    assert {:ok, msg} = ExICE.Priv.DNS.Message.decode(packet)
    assert msg.question == [%{qtype: :a, qclass: :in, qname: @addr, unicast_response: false}]

    # provide response
    response = mdns_response()

    assert {:noreply, state} =
             ExICE.Priv.MDNS.Resolver.handle_info({:udp, nil, nil, nil, response}, state)

    # if timer fires once again (because it was scheduled previously), nothing should happen
    assert {:noreply, _state} = ExICE.Priv.MDNS.Resolver.handle_info({:rtx, @addr}, state)
    assert Transport.Mock.recv(state.socket) == nil

    Transport.Mock.close(state.socket)
  end

  test "query cache" do
    assert {:ok, state, {:continue, nil}} = ExICE.Priv.MDNS.Resolver.init(Transport.Mock)
    assert {:noreply, state} = ExICE.Priv.MDNS.Resolver.handle_continue(nil, state)
    state = put_in(state, [:cache, @addr], {192, 168, 0, 1})

    # assert we get the response immediately
    assert {:reply, {:ok, {192, 168, 0, 1}}, _state} =
             ExICE.Priv.MDNS.Resolver.handle_call(
               {:gethostbyname, @addr},
               {self(), make_ref()},
               state
             )

    # assert that we didn't send any query
    assert Transport.Mock.recv(state.socket) == nil

    Transport.Mock.close(state.socket)
  end

  test "response timeout" do
    assert {:ok, state, {:continue, nil}} = ExICE.Priv.MDNS.Resolver.init(Transport.Mock)
    assert {:noreply, state} = ExICE.Priv.MDNS.Resolver.handle_continue(nil, state)

    assert {:noreply, state} =
             ExICE.Priv.MDNS.Resolver.handle_call(
               {:gethostbyname, @addr},
               {self(), make_ref()},
               state
             )

    assert {:noreply, state} =
             ExICE.Priv.MDNS.Resolver.handle_info({:response_timeout, @addr}, state)

    assert_receive {_ref, {:error, :timeout}}

    Transport.Mock.close(state.socket)
  end

  defp mdns_response() do
    %ExICE.Priv.DNS.Message{
      qr: true,
      aa: true,
      answer: [
        %{
          name: @addr,
          type: :a,
          ttl: 120,
          flush_cache: true,
          class: :in,
          rdata: <<192, 168, 0, 1>>
        }
      ]
    }
    |> ExICE.Priv.DNS.Message.encode()
  end
end
