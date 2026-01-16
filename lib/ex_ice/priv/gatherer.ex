defmodule ExICE.Priv.Gatherer do
  @moduledoc false

  alias ExICE.ICEAgent
  alias ExICE.Priv.{Candidate, Transport, Utils}
  alias ExSTUN.Message
  alias ExSTUN.Message.Type

  import Bitwise

  require Logger

  @type t() :: %__MODULE__{
          if_discovery_module: module(),
          transport_module: module(),
          ip_filter: (:inet.ip_address() -> boolean),
          ports: Enumerable.t(non_neg_integer())
        }

  @enforce_keys [:if_discovery_module, :transport_module, :ip_filter, :ports]
  defstruct @enforce_keys

  @spec new(module(), module(), fun(), Enumerable.t(non_neg_integer())) :: t()
  def new(if_discovery_module, transport_module, ip_filter, ports) do
    %__MODULE__{
      if_discovery_module: if_discovery_module,
      transport_module: transport_module,
      ip_filter: ip_filter,
      ports: ports
    }
  end

  @spec open_sockets(t()) :: {:ok, [term()]}
  def open_sockets(gatherer) do
    with {:ok, ints} <- gatherer.if_discovery_module.getifaddrs() do
      ips =
        ints
        |> Stream.reject(&loopback_if?(&1))
        |> Stream.flat_map(&get_addrs(&1))
        |> Stream.filter(&gatherer.ip_filter.(&1))
        |> Stream.reject(&unsupported_ipv6?(&1))
        |> Enum.to_list()

      ips
      |> Enum.map(&open_socket(gatherer, &1))
      |> Enum.reject(&(&1 == nil))
      |> then(&{:ok, &1})
    end
  end

  defp open_socket(gatherer, ip) do
    inet =
      case ip do
        {_, _, _, _} -> :inet
        {_, _, _, _, _, _, _, _} -> :inet6
      end

    socket_opts = [
      {:inet_backend, :socket},
      {:ip, ip},
      {:active, true},
      :binary,
      inet
    ]

    gatherer.ports
    |> Enum.shuffle()
    |> Enum.reduce_while(nil, fn port, _ ->
      case gatherer.transport_module.open(port, socket_opts) do
        {:ok, socket} ->
          {:ok, {^ip, sock_port}} = gatherer.transport_module.sockname(socket)

          Logger.debug(
            "Successfully opened socket for: #{inspect(ip)}:#{sock_port}, socket: #{inspect(socket)}"
          )

          {:halt, socket}

        {:error, :eaddrinuse} ->
          Logger.debug("Address #{inspect(ip)}:#{inspect(port)} in use. Trying next port.")
          {:cont, nil}

        {:error, reason} ->
          Logger.debug("Couldn't open socket for ip: #{inspect(ip)}. Reason: #{inspect(reason)}.")
          {:halt, nil}
      end
    end)
  end

  @spec gather_host_candidates(t(), %{:inet.ip_address() => non_neg_integer()}, [
          Transport.socket()
        ]) :: [Candidate.t()]
  def gather_host_candidates(gatherer, local_preferences, sockets) do
    {local_preferences, cands} =
      Enum.reduce(sockets, {local_preferences, []}, fn socket, {local_preferences, cands} ->
        {local_preferences, cand} = create_new_host_candidate(gatherer, local_preferences, socket)
        {local_preferences, [cand | cands]}
      end)

    {local_preferences, Enum.reverse(cands)}
  end

  @spec gather_srflx_candidate(t(), integer(), Transport.socket(), ExSTUN.URI.t()) ::
          :ok | {:error, term()}
  def gather_srflx_candidate(gatherer, t_id, socket, stun_server) do
    binding_request =
      Message.new(t_id, %Type{class: :request, method: :binding}, [])
      |> Message.encode()

    ret =
      stun_server.host
      |> then(&String.to_charlist(&1))
      |> :inet.gethostbyname()

    case ret do
      {:ok, {:hostent, _, _, _, _, ips}} ->
        ip = List.first(ips)
        port = stun_server.port

        {:ok, {sock_ip, _sock_port}} = gatherer.transport_module.sockname(socket)

        cand_family = Utils.family(sock_ip)
        stun_family = Utils.family(ip)

        if cand_family == stun_family do
          gatherer.transport_module.send(socket, {ip, port}, binding_request)
        else
          Logger.debug("""
          Not gathering srflx candidate because of incompatible ip address families.
          Socket family: #{inspect(cand_family)}
          STUN server family: #{inspect(stun_family)}
          Socket: #{inspect(sock_ip)}
          STUN server: #{inspect(stun_server)}
          """)

          {:error, :non_matching_addr_family}
        end

      {:error, reason} ->
        Logger.debug("Couldn't resolve STUN address: #{stun_server.host}, reason: #{reason}.")
        {:error, :invalid_stun_server}
    end
  end

  @spec fabricate_srflx_candidates([Candidate.Host.t()], ICEAgent.host_to_srflx_ip_mapper(), %{
          :inet.ip_address() => non_neg_integer()
        }) :: [Candidate.Srflx.t()]
  def fabricate_srflx_candidates(_host_cands, nil, _local_preferences) do
    []
  end

  def fabricate_srflx_candidates(host_cands, host_to_srflx_ip_mapper, local_preferences) do
    do_fabricate_srflx_candidates(
      host_cands,
      host_to_srflx_ip_mapper,
      local_preferences,
      [],
      []
    )
  end

  defp do_fabricate_srflx_candidates(
         [],
         _host_to_srflx_ip_mapper,
         _local_preferences,
         srflx_cands,
         _external_ips
       ) do
    srflx_cands
  end

  defp do_fabricate_srflx_candidates(
         [host_cand | rest],
         host_to_srflx_ip_mapper,
         local_preferences,
         srflx_cands,
         external_ips
       ) do
    external_ip = host_to_srflx_ip_mapper.(host_cand.base.address)

    if valid_external_ip?(external_ip, host_cand.base.address, external_ips) do
      priority =
        Candidate.priority!(local_preferences, host_cand.base.address, :srflx)

      cand =
        Candidate.Srflx.new(
          address: external_ip,
          port: host_cand.base.port,
          base_address: host_cand.base.address,
          base_port: host_cand.base.port,
          priority: priority,
          transport_module: host_cand.base.transport_module,
          socket: host_cand.base.socket
        )

      Logger.debug("New srflx candidate from NAT mapping: #{inspect(cand)}")

      do_fabricate_srflx_candidates(
        rest,
        host_to_srflx_ip_mapper,
        local_preferences,
        [cand | srflx_cands],
        [external_ip | external_ips]
      )
    else
      do_fabricate_srflx_candidates(
        rest,
        host_to_srflx_ip_mapper,
        local_preferences,
        srflx_cands,
        external_ips
      )
    end
  end

  defp valid_external_ip?(external_ip, host_ip, external_ips) do
    same_type? = :inet.is_ipv4_address(external_ip) == :inet.is_ipv4_address(host_ip)

    cond do
      host_ip == external_ip ->
        log_warning(host_ip, external_ip, "external IP is the same as local IP")
        false

      not :inet.is_ip_address(external_ip) or not same_type? ->
        log_warning(host_ip, external_ip, "not valid IP address")
        false

      external_ip in external_ips ->
        log_warning(host_ip, external_ip, "address already in use")
        false

      true ->
        true
    end
  end

  defp log_warning(host_ip, external_ip, reason),
    do:
      Logger.warning(
        "Ignoring NAT mapping: #{inspect(host_ip)} to #{inspect(external_ip)}, #{inspect(reason)}"
      )

  defp loopback_if?({_int_name, int}) do
    :loopback in int[:flags]
  end

  defp unsupported_ipv6?({_a, _b, _c, _d}), do: false

  defp unsupported_ipv6?({a, _b, _c, _d, _e, _f, _g, _h} = ip) do
    # ipv4-compatible ipv6
    # ipv6 site-local unicast
    res = match?({0, 0, 0, 0, 0, 0, _g, _h}, ip) or a >>> 6 == 0b1111111011

    if res do
      Logger.debug("Rejecting unsupported IPv6: #{inspect(ip)}.")
    end

    res
  end

  defp get_addrs({_int_name, int}) do
    # one interface can have multiple addresses
    # each address is under `:addr` key
    Keyword.get_values(int, :addr)
  end

  defp create_new_host_candidate(gatherer, local_preferences, socket) do
    {:ok, {sock_ip, sock_port}} = gatherer.transport_module.sockname(socket)

    {local_preferences, priority} = Candidate.priority(local_preferences, sock_ip, :host)

    cand =
      Candidate.Host.new(
        address: sock_ip,
        port: sock_port,
        base_address: sock_ip,
        base_port: sock_port,
        priority: priority,
        transport_module: gatherer.transport_module,
        socket: socket
      )

    Logger.debug("New candidate: #{inspect(cand)}")

    {local_preferences, cand}
  end
end
