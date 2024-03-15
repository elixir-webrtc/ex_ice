defmodule ExICE.Gatherer do
  @moduledoc false

  alias ExICE.{Candidate, Utils}
  alias ExSTUN.Message
  alias ExSTUN.Message.Type

  import Bitwise

  require Logger

  @type t() :: %__MODULE__{
          if_discovery_module: module(),
          transport_module: module(),
          ip_filter: (:inet.ip_address() -> boolean)
        }

  @enforce_keys [:if_discovery_module, :transport_module, :ip_filter]
  defstruct @enforce_keys

  @spec new(module(), module(), fun()) :: t()
  def new(if_discovery_module, transport_module, ip_filter) do
    %__MODULE__{
      if_discovery_module: if_discovery_module,
      transport_module: transport_module,
      ip_filter: ip_filter
    }
  end

  @spec gather_host_candidates(t()) :: {:ok, [Candidate.t()]} | {:error, term()}
  def gather_host_candidates(gatherer) do
    with {:ok, ints} <- gatherer.if_discovery_module.getifaddrs() do
      ips =
        ints
        |> Stream.reject(&loopback_if?(&1))
        |> Stream.flat_map(&get_addrs(&1))
        |> Stream.filter(&gatherer.ip_filter.(&1))
        |> Stream.reject(&unsupported_ipv6?(&1))
        |> Enum.to_list()

      ips
      |> Enum.map(&create_new_host_candidate(gatherer, &1))
      |> Enum.reject(&(&1 == nil))
      |> then(&{:ok, &1})
    end
  end

  @spec gather_srflx_candidate(t(), integer(), Candidate.t(), ExSTUN.URI.t()) ::
          :ok | {:error, term()}
  def gather_srflx_candidate(gatherer, t_id, host_candidate, stun_server) do
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

        cand_family = Utils.family(host_candidate.base_address)
        stun_family = Utils.family(ip)

        if cand_family == stun_family do
          gatherer.transport_module.send(host_candidate.socket, {ip, port}, binding_request)
        else
          Logger.debug("""
          Not gathering srflx candidate becasue of incompatible ip adress families.
          Candidate family: #{inspect(cand_family)}
          STUN server family: #{inspect(stun_family)}
          Candidate: #{inspect(host_candidate)}
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

  defp create_new_host_candidate(gatherer, ip) do
    inet =
      case ip do
        {_, _, _, _} -> :inet
        {_, _, _, _, _, _, _, _} -> :inet6
      end

    with {:ok, socket} <-
           gatherer.transport_module.open(0, [
             {:inet_backend, :socket},
             {:ip, ip},
             {:active, true},
             :binary,
             inet
           ]),
         {:ok, {_ip, port}} <- gatherer.transport_module.sockname(socket) do
      c = Candidate.new(:host, ip, port, ip, port, socket)

      Logger.debug("New candidate: #{inspect(c)}")

      c
    else
      {:error, reason} ->
        Logger.debug(
          "Couldn't create candidate for ip: #{inspect(ip)}. Reason: #{inspect(reason)}."
        )

        nil
    end
  end
end
