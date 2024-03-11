defmodule ExICE.MDNS.ResolverTest do
  use ExUnit.Case, async: true

  alias ExICE.Support.Transport

  @addr "somemockaddress.local"

  describe "gethostbyname/1" do
    setup do
      assert {:ok, state, {:continue, nil}} = ExICE.MDNS.Resolver.init(Transport.Mock)
      assert {:noreply, state} = ExICE.MDNS.Resolver.handle_continue(nil, state)

      assert {:noreply, state} =
               ExICE.MDNS.Resolver.handle_call(
                 {:gethostbyname, @addr},
                 {self(), make_ref()},
                 state
               )

      assert packet = Transport.Mock.recv(state.socket)
      assert is_binary(packet)
      assert {:ok, msg} = ExICE.DNS.Message.decode(packet)
      assert msg.qr == false
      assert msg.question == [%{qtype: :a, qclass: :in, qname: @addr, unicast_response: true}]

      on_exit(fn -> Transport.Mock.close(state.socket) end)

      %{state: state}
    end

    test "correct response", %{state: state} do
      response =
        %ExICE.DNS.Message{
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
        |> ExICE.DNS.Message.encode()

      assert {:noreply, _state} =
               ExICE.MDNS.Resolver.handle_info({:udp, nil, nil, nil, response}, state)

      assert_receive {_ref, {:ok, addr}}
      assert addr == {192, 168, 0, 1}
    end

    test "incorrect response", %{state: state} do
      response =
        %ExICE.DNS.Message{
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
        |> ExICE.DNS.Message.encode()

      assert {:noreply, _state} =
               ExICE.MDNS.Resolver.handle_info({:udp, nil, nil, nil, response}, state)

      refute_received {_ref, {:ok, _addr}}
    end
  end

  test "timeout" do
    assert {:ok, state, {:continue, nil}} = ExICE.MDNS.Resolver.init(Transport.Mock)
    assert {:noreply, state} = ExICE.MDNS.Resolver.handle_continue(nil, state)

    assert {:noreply, state} =
             ExICE.MDNS.Resolver.handle_call({:gethostbyname, @addr}, {self(), make_ref()}, state)

    assert {:noreply, state} = ExICE.MDNS.Resolver.handle_info({:response_timeout, @addr}, state)
    assert_receive {_ref, {:error, :timeout}}

    Transport.Mock.close(state.socket)
  end
end
