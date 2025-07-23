defmodule ExICE.Priv.NATMapper do
  @moduledoc false

  require Logger

  alias ExICE.ICEAgent
  alias ExICE.Priv.Candidate

  @spec create_srflx_candidates([Candidate.Host.t()], ICEAgent.map_to_nat_ip(), %{
          :inet.ip_address() => non_neg_integer()
        }) :: [Candidate.Srflx.t()]
  def create_srflx_candidates(_host_cands, nil, _local_preferences) do
    []
  end

  def create_srflx_candidates(host_cands, map_to_nat_ip, local_preferences) do
    {cands, _external_ips} =
      Enum.reduce(host_cands, {[], []}, fn host_cand, {cands, external_ips} ->
        external_ip = map_to_nat_ip.(host_cand.base.address)

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

          {[cand | cands], [external_ip | external_ips]}
        else
          {cands, external_ips}
        end
      end)

    cands
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
end
