defmodule ExICE.Gatherer do
  @moduledoc false

  alias ExICE.Candidate
  alias ExSTUN.Message
  alias ExSTUN.Message.Type
  alias ExSTUN.Message.Attribute.XORMappedAddress

  import Bitwise

  require Logger

  @spec gather_host_candidates() :: {:ok, [Candidate.t()]} | {:error, term()}
  def gather_host_candidates() do
    with {:ok, ints} <- :inet.getifaddrs() do
      ips =
        ints
        |> Stream.reject(&is_loopback_if(&1))
        |> Stream.flat_map(&get_addrs(&1))
        |> Stream.reject(&is_unsupported_ipv6(&1))
        |> Enum.to_list()

      ips
      |> Enum.map(&create_new_host_candidate(&1))
      |> Enum.reject(&(&1 == nil))
      |> then(&{:ok, &1})
    end
  end

  @spec gather_srflx_candidate(pid(), Candidate.t(), ExICE.URI.t()) :: :ok
  def gather_srflx_candidate(controlling_process, host_candidate, stun_server) do
    Logger.debug(
      "Trying to gather srflx candidate for #{inspect(host_candidate)}, #{inspect(stun_server)}"
    )

    # try to gather srflx candidate
    # if successful, send result back to controlling process
    # if not, just terminate

    binding_request =
      %Type{class: :request, method: :binding}
      |> Message.new()
      |> Message.encode()

    {:ok, {:hostent, _, _, _, _, ips}} =
      stun_server.host
      |> then(&String.to_charlist(&1))
      |> :inet_res.gethostbyname()

    ip = List.first(ips)
    port = stun_server.port
    :ok = :gen_udp.send(host_candidate.socket, {ip, port}, binding_request)

    {:ok, {_addr, _port, binding_response}} = :gen_udp.recv(host_candidate.socket, 0)

    {:ok, msg} = ExSTUN.Message.decode(binding_response)

    Message.get_attribute(msg, XORMappedAddress)

    send(controlling_process, {:new_candidate, nil})
    :ok
  end

  defp is_loopback_if({_int_name, int}) do
    :loopback in int[:flags]
  end

  defp is_unsupported_ipv6({_a, _b, _c, _d}), do: false

  defp is_unsupported_ipv6({a, _b, _c, _d, _e, _f, _g, _h} = ip) do
    # ipv4-compatible ipv6
    # ipv6 site-local unicast
    res = match?({0, 0, 0, 0, 0, 0, _g, _h}, ip) or a >>> 2 == 0b1111111011

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

  defp create_new_host_candidate(ip) do
    inet =
      case ip do
        {_, _, _, _} -> :inet
        {_, _, _, _, _, _, _, _} -> :inet6
      end

    with {:ok, socket} <-
           :gen_udp.open(0, [
             {:inet_backend, :socket},
             {:active, true},
             :binary,
             inet
           ]),
         {:ok, port} <- :inet.port(socket) do
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
