defmodule ExICE.Priv.Gatherer do
  @moduledoc false

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

    Enum.reduce_while(gatherer.ports, nil, fn port, _ ->
      case gatherer.transport_module.open(port, socket_opts) do
        {:ok, socket} ->
          {:ok, {^ip, sock_port}} = gatherer.transport_module.sockname(socket)
          Logger.debug("Successfully opened socket for: #{inspect(ip)}:#{sock_port}")
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

  @spec gather_host_candidates(t(), [Transport.socket()]) :: [Candidate.t()]
  def gather_host_candidates(gatherer, sockets) do
    Enum.map(sockets, &create_new_host_candidate(gatherer, &1))
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
        end

      {:error, reason} ->
        Logger.debug("Couldn't resolve STUN address: #{stun_server.host}, reason: #{reason}.")
        {:error, :invalid_stun_server}
    end
  end

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

  defp create_new_host_candidate(gatherer, socket) do
    {:ok, {sock_ip, sock_port}} = gatherer.transport_module.sockname(socket)

    cand =
      Candidate.Host.new(
        address: sock_ip,
        port: sock_port,
        base_address: sock_ip,
        base_port: sock_port,
        transport_module: gatherer.transport_module,
        socket: socket
      )

    Logger.debug("New candidate: #{inspect(cand)}")

    cand
  end
end
