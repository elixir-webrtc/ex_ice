defmodule ExICE.Priv.Candidate.RelayTest do
  use ExUnit.Case, async: true

  alias ExICE.Priv.Candidate.Relay
  alias ExICE.Support.Transport

  @turn_ip {192, 0, 2, 1}
  @peer_ip {192, 0, 2, 10}
  @peer_port 50_000

  setup do
    Transport.Mock.init()
    port = 5000 + System.unique_integer([:positive])
    {:ok, socket} = Transport.Mock.setup_socket({192, 0, 2, 2}, port)
    {:ok, uri} = ExSTUN.URI.parse("turn:192.0.2.1:3478?transport=udp")
    {:ok, client} = ExTURN.Client.new(uri, "testusername", "testpassword")

    cand =
      Relay.new(
        address: @turn_ip,
        port: 12_345,
        priority: 123,
        transport_module: Transport.Mock,
        socket: socket,
        client: %{client | state: :error}
      )

    %{cand: cand, socket: socket}
  end

  describe "send_data/4 with a TURN client in the error state" do
    test "returns an error when no permission exists", %{cand: cand, socket: socket} do
      assert {:error, _reason, %Relay{}} = Relay.send_data(cand, @peer_ip, @peer_port, "data")
      assert nil == Transport.Mock.recv(socket)
    end

    test "returns an error when a permission and a channel exist", %{cand: cand, socket: socket} do
      client = %{
        cand.client
        | permissions: %{@peer_ip => %{refresh_timer: nil, exp_timer: nil}},
          addr_channel: %{{@peer_ip, @peer_port} => 0x4000},
          channel_addr: %{0x4000 => {@peer_ip, @peer_port}}
      }

      cand = %{cand | client: client}

      assert {:error, _reason, %Relay{}} = Relay.send_data(cand, @peer_ip, @peer_port, "data")
      assert nil == Transport.Mock.recv(socket)
    end
  end
end
