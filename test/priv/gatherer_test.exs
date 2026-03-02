defmodule ExICE.Priv.GathererTest do
  use ExUnit.Case, async: true

  alias ExICE.Priv.{Candidate, Gatherer}

  alias ExICE.Support.Transport

  alias ExSTUN.Message.Type

  defmodule IfDiscovery.Mock do
    @behaviour ExICE.Priv.IfDiscovery

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
      Gatherer.new(
        IfDiscovery.Mock,
        Transport.Mock,
        fn
          {192, 168, 0, 2} -> false
          _ -> true
        end,
        [0]
      )

    assert {:ok, sockets} = Gatherer.open_sockets(gatherer)

    # there should only be one candidate
    assert {local_preferences, [%Candidate.Host{} = c]} =
             Gatherer.gather_host_candidates(gatherer, %{}, sockets)

    assert Map.has_key?(local_preferences, c.base.address)
    assert map_size(local_preferences) == 1
    assert c.base.address == {192, 168, 0, 1}
    assert c.base.base_address == {192, 168, 0, 1}
    assert c.base.port == c.base.base_port
    assert c.base.type == :host
  end

  test "gather_srflx_candidate/4" do
    {:ok, stun_server} = ExSTUN.URI.parse("stun:192.168.0.3:19302")

    gatherer =
      Gatherer.new(
        IfDiscovery.Mock,
        Transport.Mock,
        fn
          {192, 168, 0, 2} -> false
          _ -> true
        end,
        [0]
      )

    {:ok, sockets} = Gatherer.open_sockets(gatherer)

    {_local_preferences, [%Candidate.Host{} = c]} =
      Gatherer.gather_host_candidates(gatherer, %{}, sockets)

    assert :ok = Gatherer.gather_srflx_candidate(gatherer, 1234, c.base.socket, stun_server)
    assert packet = Transport.Mock.recv(c.base.socket)
    assert {:ok, req} = ExSTUN.Message.decode(packet)
    assert req.attributes == []
    assert req.type == %Type{class: :request, method: :binding}
  end

  test "use custom port range" do
    port_range = 55_000..55_001

    gatherer =
      Gatherer.new(
        IfDiscovery.Mock,
        Transport.Mock,
        fn
          {192, 168, 0, 2} -> false
          _ -> true
        end,
        port_range
      )

    {:ok, sockets} = Gatherer.open_sockets(gatherer)

    for %{socket: socket} <- sockets do
      {:ok, {_ip, port}} = Transport.Mock.sockname(socket)
      assert port in port_range
    end
  end

  describe "host to prefabricated srflx mapper" do
    @ipv4 {10, 10, 10, 10}
    @ipv6 {64_512, 0, 0, 0, 0, 0, 0, 1}
    @invalid_ip :invalid_ip

    @ipv4_filter &:inet.is_ipv4_address(&1)

    test "adds srflx candidate" do
      ip_filter = fn
        {192, 168, 0, 2} -> false
        _ -> true
      end

      {local_preferences, host_cands} = setup_gatherer(ip_filter)

      assert [%Candidate.Srflx{base: %{address: @ipv4}}] =
               Gatherer.fabricate_srflx_candidates(
                 host_cands,
                 fn _ip -> @ipv4 end,
                 local_preferences
               )
    end

    test "creates only one candidate if external ip is repeated" do
      {local_preferences, host_cands} = setup_gatherer(@ipv4_filter)

      assert [%Candidate.Srflx{base: %{address: @ipv4}}] =
               Gatherer.fabricate_srflx_candidates(
                 host_cands,
                 fn _ip -> @ipv4 end,
                 local_preferences
               )
    end

    test "ignores one to one mapping" do
      {local_preferences, host_cands} = setup_gatherer(@ipv4_filter)

      assert [] ==
               Gatherer.fabricate_srflx_candidates(
                 host_cands,
                 fn ip -> ip end,
                 local_preferences
               )
    end

    test "ignores if ip types is not the same" do
      {local_preferences, host_cands} = setup_gatherer(@ipv4_filter)

      assert [] ==
               Gatherer.fabricate_srflx_candidates(
                 host_cands,
                 fn _ip -> @ipv6 end,
                 local_preferences
               )
    end

    test "ignores when function returns nil value" do
      {local_preferences, host_cands} = setup_gatherer(@ipv4_filter)

      assert [] ==
               Gatherer.fabricate_srflx_candidates(
                 host_cands,
                 fn _ip -> nil end,
                 local_preferences
               )
    end

    test "ignores when function returns invalid value" do
      {local_preferences, host_cands} = setup_gatherer(@ipv4_filter)

      assert [] ==
               Gatherer.fabricate_srflx_candidates(
                 host_cands,
                 fn _ip -> @invalid_ip end,
                 local_preferences
               )
    end

    defp setup_gatherer(ip_filter) do
      gatherer = Gatherer.new(IfDiscovery.Mock, Transport.Mock, ip_filter, [0])
      assert {:ok, sockets} = Gatherer.open_sockets(gatherer)

      Gatherer.gather_host_candidates(gatherer, %{}, sockets)
    end
  end
end
