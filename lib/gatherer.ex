defmodule ExIce.Gatherer do
  alias ExIce.Candidate

  use Bitwise

  require Logger

  @spec gather_host_candidates(pid()) :: {:ok, [Candidate.t()]} | {:error, term()}
  def gather_host_candidates(controlling_process) do
    with {:ok, ints} <- :inet.getifaddrs() do
      ips =
        ints
        |> Stream.reject(&is_loopback_if(&1))
        |> Stream.flat_map(&get_addrs(&1))
        |> Stream.reject(&is_unsupported_ipv6(&1))
        |> Enum.to_list()

      ips
      |> Enum.map(&create_new_host_candidate(&1, controlling_process))
      |> Enum.filter(&(&1 == nil))
      |> then(&{:ok, &1})
    end
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

  defp create_new_host_candidate(ip, controlling_process) do
    with {:ok, socket} <- :gen_udp.open(0, active: true),
         {:ok, port} = :inet.port(socket) do
      c = %Candidate{
        address: ip,
        base_address: ip,
        base_port: port,
        port: port,
        priority: 0,
        socket: socket,
        type: :host
      }

      Logger.debug("New candidate: #{inspect(c)}")

      send(controlling_process, {:new_candidate, c})

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
