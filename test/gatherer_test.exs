defmodule ExICE.GathererTest do
  use ExUnit.Case

  alias ExICE.{Candidate, Gatherer}

  alias ExICE.Support.Transport

  alias ExSTUN.Message.Type

  defmodule IfDiscovery.Mock do
    @behaviour ExICE.IfDiscovery

    @impl true
    def getifaddrs() do
      ifs = [
        {~c"mockif0", [{:flags, [:up, :running]}, {:addr, {192, 168, 0, 1}}]},
        {~c"mockif1", [{:flags, [:up, :running]}, {:addr, {192, 168, 0, 2}}]},
        # loopback
        {~c"mockif2", [{:flags, [:up, :running, :loopback]}, {:addr, {127, 0, 0, 1}}]},
        # ipv4-compatible ipv6
        {~c"mockif3", [{:flags, [:up, :running]}, {:addr, {0, 0, 0, 0, 0, 0, 84, 45}}]},
        # site-local unicast ipv6
        {~c"mockif4", [{:flags, [:up, :running]}, {:addr, {0xFEC0, 0, 0, 0, 0, 0, 84, 45}}]}
      ]

      {:ok, ifs}
    end
  end

  test "gather_host_candidates/1" do
    gatherer =
      Gatherer.new(IfDiscovery.Mock, Transport.Mock, fn
        {192, 168, 0, 2} -> false
        _ -> true
      end)

    # there should only be one candidate
    assert {:ok, [%Candidate{} = c]} = Gatherer.gather_host_candidates(gatherer)
    assert c.address == {192, 168, 0, 1}
    assert c.base_address == {192, 168, 0, 1}
    assert c.port == c.base_port
    assert c.type == :host
  end

  test "gather_srflx_candidate/4" do
    {:ok, stun_server} = ExICE.URI.parse("stun:192.168.0.3:19302")

    gatherer =
      Gatherer.new(IfDiscovery.Mock, Transport.Mock, fn
        {192, 168, 0, 2} -> false
        _ -> true
      end)

    {:ok, [%Candidate{} = c]} = Gatherer.gather_host_candidates(gatherer)

    assert :ok = Gatherer.gather_srflx_candidate(gatherer, 1234, c, stun_server)
    assert [{_socket, packet}] = :ets.lookup(:transport_mock, c.socket)
    assert {:ok, req} = ExSTUN.Message.decode(packet)
    assert req.attributes == []
    assert req.type == %Type{class: :request, method: :binding}
  end
end
