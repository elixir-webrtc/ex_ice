defmodule ExICE.Priv.MDNS.Resolver do
  @moduledoc false
  # This is based on https://datatracker.ietf.org/doc/html/draft-ietf-mmusic-mdns-ice-candidates#section-3.2.1

  use GenServer, restart: :transient

  require Logger

  @mdns_port 5353
  @multicast_addr {{224, 0, 0, 251}, @mdns_port}
  @response_timeout_ms 3000
  @rtx_timeout_ms 500

  @spec start_link(module()) :: GenServer.on_start()
  def start_link(transport_module \\ :gen_udp) do
    GenServer.start_link(__MODULE__, transport_module, name: __MODULE__)
  end

  @spec gethostbyname(String.t()) :: {:ok, :inet.ip_address()} | {:error, term()}
  def gethostbyname(addr) do
    try do
      GenServer.call(__MODULE__, {:gethostbyname, addr})
    catch
      :exit, {:timeout, _} ->
        {:error, :timeout}
    end
  end

  @impl true
  def init(transport_module) do
    Logger.debug("Starting MDNS Resolver")
    {:ok, %{transport_module: transport_module, cache: %{}}, {:continue, nil}}
  end

  @impl true
  def handle_continue(_, state) do
    ret =
      state.transport_module.open(
        # Listen on the port specific to mDNS traffic.
        # `add_membership` option only defines an address.
        @mdns_port,
        mode: :binary,
        reuseaddr: true,
        active: true,
        # Allow other apps to bind to @mdns_port.
        # If there are multiple sockets, bound to the same port,
        # and subscribed to the same group (in fact, if one socket
        # subscribes to some group, all other sockets bound to
        # the same port also join this group), all those sockets
        # will receive every message. In other words, `reuseport` for
        # multicast works differently than for casual sockets.
        reuseport: true,
        # Support running two ICE agents on a single machine.
        # In other case, our request won't be delivered to the mDNS address owner
        # running on the same machine (e.g., a web browser).
        multicast_loop: true,
        # Receive responses - they are sent to the multicast address.
        # The second argument specifies interfaces where we should listen
        # for multicast traffic.
        # This option works on interfaces i.e. it affects all sockets
        # bound to the same port.
        add_membership: {{224, 0, 0, 251}, {0, 0, 0, 0}}
      )

    case ret do
      {:ok, socket} ->
        state = Map.merge(state, %{socket: socket, queries: %{}})
        {:noreply, state}

      {:error, reason} ->
        Logger.warning("""
        Couldn't start MDNS resolver, reason: #{reason}. MDNS candidates won't be resolved.
        """)

        {:stop, {:shutdown, reason}, state}
    end
  end

  @impl true
  def handle_call({:gethostbyname, addr}, _from, %{cache: cache} = state)
      when is_map_key(cache, addr) do
    {:reply, {:ok, Map.fetch!(cache, addr)}, state}
  end

  @impl true
  def handle_call({:gethostbyname, addr}, from, state) do
    if Map.has_key?(state.queries, addr) do
      query_info = Map.fetch!(state.queries, addr)
      requesters = [from | query_info.requesters]
      query_info = %{query_info | requesters: requesters}
      state = put_in(state, [:queries, addr], query_info)
      {:noreply, state}
    else
      query =
        %ExICE.Priv.DNS.Message{
          question: [
            %{
              qname: addr,
              qtype: :a,
              qclass: :in,
              unicast_response: true
            }
          ]
        }
        |> ExICE.Priv.DNS.Message.encode()

      case state.transport_module.send(state.socket, @multicast_addr, query) do
        :ok ->
          Process.send_after(self(), {:response_timeout, addr}, @response_timeout_ms)
          rtx_timer = Process.send_after(self(), {:rtx, addr}, @rtx_timeout_ms)
          state = put_in(state, [:queries, addr], %{requesters: [from], rtx_timer: rtx_timer})
          {:noreply, state}

        {:error, reason} ->
          {:reply, {:error, reason}, state}
      end
    end
  end

  @impl true
  def handle_info({:udp, _socket, _ip, _port, packet}, state) do
    case ExICE.Priv.DNS.Message.decode(packet) do
      # Only accept query response with one resource record.
      # See https://datatracker.ietf.org/doc/html/draft-ietf-mmusic-mdns-ice-candidates#section-3.2.2
      {:ok, %{qr: true, aa: true, answer: [%{type: :a, class: :in, rdata: <<a, b, c, d>>} = rr]}} ->
        uuid4 = ice_name?(rr.name)
        {query_info, state} = pop_in(state, [:queries, rr.name])
        addr = {a, b, c, d}

        case {uuid4, query_info} do
          # Name is in the form of uuid4 and we didn't ask for it.
          # This should be an announcement - save it in the cache.
          # See: https://issues.chromium.org/issues/339829283
          {true, nil} ->
            state = put_in(state, [:cache, rr.name], addr)
            {:noreply, state}

          {false, nil} ->
            {:noreply, state}

          {true, %{requesters: requesters}} ->
            Process.cancel_timer(query_info.rtx_timer)
            for requester <- requesters, do: :ok = GenServer.reply(requester, {:ok, addr})
            Process.send_after(self(), {:ttl_expired, rr.name}, rr.ttl * 1000)
            state = put_in(state, [:cache, rr.name], addr)
            {:noreply, state}
        end

      _other ->
        {:noreply, state}
    end
  end

  @impl true
  def handle_info({:response_timeout, addr}, state) do
    case pop_in(state, [:queries, addr]) do
      {nil, state} ->
        {:noreply, state}

      {%{requesters: requesters}, state} ->
        for requester <- requesters, do: :ok = GenServer.reply(requester, {:error, :timeout})
        {:noreply, state}
    end
  end

  @impl true
  def handle_info({:rtx, addr}, %{queries: queries} = state) when is_map_key(queries, addr) do
    # rtx messages should be casual QM questions - no unicast-response flag set
    query =
      %ExICE.Priv.DNS.Message{
        question: [
          %{
            qname: addr,
            qtype: :a,
            qclass: :in,
            unicast_response: false
          }
        ]
      }
      |> ExICE.Priv.DNS.Message.encode()

    state.transport_module.send(state.socket, @multicast_addr, query)
    rtx_timer = Process.send_after(self(), {:rtx, addr}, @rtx_timeout_ms)
    state = put_in(state, [:queries, addr, :rtx_timer], rtx_timer)
    {:noreply, state}
  end

  @impl true
  def handle_info({:rtx, _addr}, state) do
    {:noreply, state}
  end

  @impl true
  def handle_info({:ttl_expired, addr}, state) do
    {_, state} = pop_in(state, [:cache, addr])
    {:noreply, state}
  end

  defp ice_name?(name) do
    name
    |> String.trim_trailing(".local")
    |> uuid4?()
  end

  defp uuid4?(uuid) do
    case UUID.info(uuid) do
      {:ok, info} -> info[:version] == 4
      _ -> false
    end
  end
end
