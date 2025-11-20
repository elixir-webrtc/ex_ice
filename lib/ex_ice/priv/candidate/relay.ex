defmodule ExICE.Priv.Candidate.Relay do
  @moduledoc false
  @behaviour ExICE.Priv.Candidate

  alias ExICE.Priv.CandidateBase

  @type t() :: %__MODULE__{base: CandidateBase.t()}

  @enforce_keys [:base, :client]
  defstruct @enforce_keys ++ [buffered_packets: []]

  @impl true
  def new(config) do
    %__MODULE__{base: CandidateBase.new(:relay, config), client: Keyword.fetch!(config, :client)}
  end

  @impl true
  def marshal(cand), do: CandidateBase.marshal(cand.base)

  @impl true
  def family(cand), do: CandidateBase.family(cand.base)

  @impl true
  def tcp_type(cand), do: CandidateBase.tcp_type(cand.base)

  @impl true
  def to_candidate(cand), do: CandidateBase.to_candidate(cand.base)

  @impl true
  def send_data(cand, dst_ip, dst_port, data) do
    permission = ExTURN.Client.has_permission?(cand.client, dst_ip)
    channel = ExTURN.Client.has_channel?(cand.client, dst_ip, dst_port)

    case {permission, channel} do
      {true, true} ->
        {:send, turn_addr, data, client} =
          ExTURN.Client.send(cand.client, {dst_ip, dst_port}, data)

        cand = %{cand | client: client}
        do_send(cand, turn_addr, data)

      {true, false} ->
        {:send, turn_addr, data, client} =
          ExTURN.Client.send(cand.client, {dst_ip, dst_port}, data)

        cand = %{cand | client: client}

        case ExTURN.Client.create_channel(cand.client, dst_ip, dst_port) do
          {:ok, client} ->
            cand = %{cand | client: client}
            do_send(cand, turn_addr, data)

          {:send, ^turn_addr, channel_data, client} ->
            cand = %{cand | client: client}

            with {:ok, cand} <- do_send(cand, turn_addr, data) do
              do_send(cand, turn_addr, channel_data)
            end
        end

      {false, false} ->
        {:send, turn_addr, turn_data, client} =
          ExTURN.Client.create_permission(cand.client, dst_ip)

        buffered_data = [{dst_ip, dst_port, data} | cand.buffered_packets]
        cand = %{cand | client: client, buffered_packets: buffered_data}

        do_send(cand, turn_addr, turn_data)
    end
  end

  @spec receive_data(t(), :inet.ip_address(), :inet.port_number(), binary()) ::
          {:ok, t()}
          | {:ok, :inet.ip_address(), :inet.port_number(), t()}
          | {:error, term(), t()}
  def receive_data(cand, src_ip, src_port, data) do
    case ExTURN.Client.handle_message(cand.client, {:socket_data, src_ip, src_port, data}) do
      {:ok, client} ->
        cand = %{cand | client: client}
        {:ok, cand}

      {:permission_created, permission_ip, client} ->
        cand = %{cand | client: client}
        send_buffered_packets(cand, permission_ip)

      {:channel_created, _addr, client} ->
        cand = %{cand | client: client}
        {:ok, cand}

      {:send, dst, data, client} ->
        # this might happen when we receive stale nonce response
        cand = %{cand | client: client}
        do_send(cand, dst, data)

      {:data, {src_ip, src_port}, data, client} ->
        cand = %{cand | client: client}
        {:ok, src_ip, src_port, data, cand}

      {:error, reason, client} ->
        cand = %{cand | client: client}
        {:error, reason, cand}
    end
  end

  defp send_buffered_packets(cand, permission_ip) do
    {packets_to_send, rest} =
      Enum.split_with(cand.buffered_packets, fn {dst_ip, _dst_port, _data} ->
        dst_ip == permission_ip
      end)

    cand = %{cand | buffered_packets: rest}
    do_send_buffered_packets(cand, Enum.reverse(packets_to_send))
  end

  defp do_send_buffered_packets(cand, []), do: {:ok, cand}

  defp do_send_buffered_packets(cand, [{dst_ip, dst_port, packet} | packets]) do
    case send_data(cand, dst_ip, dst_port, packet) do
      {:ok, cand} ->
        do_send_buffered_packets(cand, packets)

      {:error, _reasons, _cand} = error ->
        error
    end
  end

  defp do_send(cand, dst_addr, data) do
    case cand.base.transport_module.send(cand.base.socket, dst_addr, data) do
      :ok -> {:ok, cand}
      {:error, reason} -> {:error, reason, cand}
    end
  end
end
