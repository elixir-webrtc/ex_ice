defmodule ExICE.ICEAgent do
  @moduledoc """
  ICE Agent.

  Not to be confused with Elixir Agent.
  """
  use GenServer

  require Logger

  alias ExICE.{Candidate, CandidatePair, Gatherer}
  alias ExICE.Attribute.{ICEControlling, ICEControlled, UseCandidate}

  alias ExSTUN.Message
  alias ExSTUN.Message.Type
  alias ExSTUN.Message.Attribute.{Username, XORMappedAddress}

  # Ta timeout in ms
  @ta_timeout 50

  @type role() :: :controlling | :controlled

  @type opts() :: [
          ip_filter: (:inet.ip_address() -> boolean),
          stun_servers: [String.t()]
        ]

  @spec start_link(role(), opts()) :: GenServer.on_start()
  def start_link(role, opts \\ []) do
    GenServer.start_link(__MODULE__, opts ++ [role: role, controlling_process: self()])
  end

  @spec run(pid()) :: :ok
  def run(ice_agent) do
    GenServer.cast(ice_agent, :run)
  end

  @spec set_remote_credentials(pid(), binary(), binary()) :: :ok
  def set_remote_credentials(ice_agent, ufrag, passwd) do
    GenServer.cast(ice_agent, {:set_remote_credentials, ufrag, passwd})
  end

  @spec gather_candidates(pid()) :: :ok
  def gather_candidates(ice_agent) do
    GenServer.cast(ice_agent, :gather_candidates)
  end

  @spec add_remote_candidate(pid(), String.t()) :: :ok
  def add_remote_candidate(ice_agent, candidate) do
    GenServer.cast(ice_agent, {:add_remote_candidate, candidate})
  end

  @spec end_of_candidates(pid()) :: :ok
  def end_of_candidates(ice_agent) do
    GenServer.cast(ice_agent, :end_of_candidates)
  end

  ### Server

  @impl true
  def init(opts) do
    stun_servers =
      opts
      |> Keyword.get(:stun_servers, [])
      |> Enum.map(fn stun_server ->
        case ExICE.URI.parse(stun_server) do
          {:ok, stun_server} ->
            stun_server

          :error ->
            Logger.warn("""
            Couldn't parse STUN server URI: #{inspect(stun_server)}. \
            Ignoring.\
            """)

            nil
        end
      end)
      |> Enum.reject(&(&1 == nil))

    state = %{
      started?: false,
      controlling_process: Keyword.fetch!(opts, :controlling_process),
      gathering_transactions: %{},
      ip_filter: opts[:ip_filter],
      role: Keyword.fetch!(opts, :role),
      checklist: [],
      tr_check_q: [],
      valid_pairs: [],
      selected_pair: nil,
      conn_checks: %{},
      gathering_state: nil,
      eoc: false,
      local_ufrag: nil,
      local_pwd: nil,
      local_cands: [],
      remote_ufrag: nil,
      remote_pwd: nil,
      remote_cands: [],
      stun_servers: stun_servers,
      turn_servers: []
    }

    {:ok, state}
  end

  @impl true
  def handle_cast(:run, %{started?: true} = state) do
    Logger.warn("ICE already started. Ignoring.")
    {:noreply, state}
  end

  @impl true
  def handle_cast(:run, state) do
    ufrag = :crypto.strong_rand_bytes(3)
    pwd = :crypto.strong_rand_bytes(16)
    state = %{state | started?: true, local_ufrag: ufrag, local_pwd: pwd}
    send(state.controlling_process, {self(), {:local_credentials, ufrag, pwd}})
    state = do_gather_candidates(state)
    {:noreply, state}
  end

  @impl true
  def handle_cast({:set_remote_credentials, ufrag, passwd}, state) do
    Logger.debug("Setting remote credentials: #{inspect(ufrag)}:#{inspect(passwd)}")
    state = %{state | remote_ufrag: ufrag, remote_pwd: passwd}
    {:noreply, state}
  end

  @impl true
  def handle_cast(:gather_candidates, state) do
    state = do_gather_candidates(state)
    {:noreply, state}
  end

  @impl true
  def handle_cast({:add_remote_candidate, _remote_cand}, %{eoc: true} = state) do
    Logger.warn("Received remote candidate after end-of-candidates. Ignoring.")
    {:noreply, state}
  end

  @impl true
  def handle_cast({:add_remote_candidate, remote_cand}, state) do
    {:ok, remote_cand} = Candidate.unmarshal(remote_cand)
    Logger.debug("New remote candidate #{inspect(remote_cand)}")
    start_ta? = state.checklist == []

    remote_cand_family = Candidate.family(remote_cand)

    local_cands = Enum.filter(state.local_cands, &(Candidate.family(&1) == remote_cand_family))

    checklist_foundations =
      for cand_pair <- state.checklist do
        {cand_pair.local_cand.foundation, cand_pair.remote_cand.foundation}
      end

    new_pairs =
      for local_cand <- local_cands do
        pair_state =
          if {local_cand.foundation, remote_cand.foundation} in checklist_foundations do
            :frozen
          else
            :waiting
          end

        pair = CandidatePair.new(local_cand, remote_cand, state.role, pair_state)

        Logger.debug("New candidate pair #{inspect(pair)}")
        pair
      end

    state = %{
      state
      | checklist: state.checklist ++ new_pairs,
        remote_cands: state.remote_cands ++ [remote_cand]
    }

    if start_ta? do
      Process.send_after(self(), :ta_timeout, @ta_timeout)
    end

    {:noreply, state}
  end

  @impl true
  def handle_cast(:end_of_candidates, %{role: :controlled} = state) do
    Logger.debug("Received end-of-candidates in role controlled.")
    {:noreply, %{state | eoc: true}}
  end

  @impl true
  def handle_cast(:end_of_candidates, %{role: :controlling} = state) do
    state = %{state | eoc: true}
    in_progress = Enum.any?(state.checklist, fn pair -> pair.state == :in_progress end)
    waiting = Enum.any?(state.checklist, fn pair -> pair.state == :waiting end)

    if waiting or in_progress do
      Logger.debug("""
      Received end-of-candidates but there are checks waiting or in-progress. \
      Waiting with nomination.
      """)

      {:noreply, state}
    else
      # TODO check whether gathering process has finished
      # pair = Enum.max_by(state.valid_pairs, fn pair -> pair.priority end)

      pair_idx =
        state.checklist
        |> Enum.with_index()
        |> Enum.filter(fn {pair, _idx} -> pair.state == :succeeded end)
        |> Enum.max_by(fn {pair, _idx} -> pair.priority end)

      if pair_idx do
        {pair, idx} = pair_idx

        Logger.debug("""
        Received end-of-candidates. There are no checks waiting or in-progress. \
        Enqueuing pair for nomination: #{inspect(pair)}"
        """)

        pair = %CandidatePair{pair | state: :waiting, nominate?: true}
        # TODO use triggered check queue
        state = update_in(state, [:checklist], &List.update_at(&1, idx, fn _ -> pair end))
        {:noreply, state}
      else
        Logger.debug("""
        Received end-of-candidates but there are no valid pairs and no checks waiting or in-progress. \
        ICE failed.
        """)

        send(state.controlling_process, {self(), :failed})
        {:noreply, state}
      end
    end
  end

  @impl true
  def handle_info(:ta_timeout, state) do
    state =
      case get_next_gathering_transaction(state.gathering_transactions) do
        {_t_id, transaction} -> handle_gathering_transaction(transaction, state)
        nil -> handle_checklist(state)
      end

    if state.selected_pair == nil do
      Process.send_after(self(), :ta_timeout, @ta_timeout)
    end

    {:noreply, state}
  end

  @impl true
  def handle_info({:udp, socket, src_ip, src_port, packet}, state) do
    if ExSTUN.is_stun(packet) do
      case ExSTUN.Message.decode(packet) do
        {:ok, msg} ->
          state = handle_stun_msg(socket, src_ip, src_port, msg, state)
          {:noreply, state}

        {:error, reason} ->
          Logger.warn("Couldn't decode stun message: #{inspect(reason)}")
          {:noreply, state}
      end
    else
      Logger.warn("Got non-stun packet: #{inspect(packet)}. Ignoring...")
      {:noreply, state}
    end
  end

  @impl true
  def handle_info(msg, state) do
    Logger.warn("Got unexpected msg: #{inspect(msg)}")
    {:noreply, state}
  end

  defp get_next_gathering_transaction(gathering_transactions) do
    Enum.find(gathering_transactions, fn {_t_id, t} -> t.state == :waiting end)
  end

  defp handle_gathering_transaction(
         %{t_id: t_id, host_cand: host_cand, stun_server: stun_server} = t,
         state
       ) do
    Logger.debug("""
    Sending binding request to gather srflx candidate for: 
    host_cand: #{inspect(host_cand)}, 
    stun_server: #{inspect(stun_server)}
    """)

    :ok = Gatherer.gather_srflx_candidate(t_id, host_cand, stun_server)
    t = %{t | state: :in_progress}
    put_in(state, [:gathering_transactions, t_id], t)
  end

  defp handle_checklist(state) do
    pair_idx =
      state.checklist
      |> Enum.with_index()
      |> Enum.filter(fn {pair, _idx} -> pair.state == :waiting end)
      |> Enum.max_by(fn {pair, _idx} -> pair.priority end, fn -> nil end)

    in_progress = Enum.any?(state.checklist, fn pair -> pair.state == :waiting end)

    case pair_idx do
      {pair, idx} ->
        Logger.debug("Sending conn check on pair: #{inspect(pair)}")

        {pair, state} = send_conn_check(pair, state)

        %{state | checklist: List.update_at(state.checklist, idx, fn _ -> pair end)}

      nil ->
        if not in_progress and state.role == :controlling do
          # nominate pair
          # TODO check whether gathering process has finished
          # pair = Enum.max_by(state.valid_pairs, fn pair -> pair.priority end)

          pair_idx =
            state.checklist
            |> Enum.with_index()
            |> Enum.filter(fn {pair, _idx} -> pair.state == :succeeded end)
            |> Enum.max_by(fn {pair, _idx} -> pair.priority end, fn -> nil end)

          if pair_idx do
            {pair, idx} = pair_idx

            Logger.debug("""
            Enqueuing pair for nomination: #{inspect(pair)}"
            """)

            pair = %CandidatePair{pair | state: :waiting, nominate?: true}
            # TODO use triggered check queue
            state = update_in(state, [:checklist], &List.update_at(&1, idx, fn _ -> pair end))

            {_, state} = handle_info(:ta_timeout, state)
            state
          else
            send(state.controlling_process, {self(), :failed})
            state
          end
        else
          state
        end
    end
  end

  defp handle_stun_msg(socket, src_ip, src_port, %Message{} = msg, state) do
    # TODO revisit 7.3.1.4
    case msg.type do
      %Type{class: :request, method: :binding} ->
        handle_binding_request(socket, src_ip, src_port, msg, state)

      %Type{class: :success_response, method: :binding} ->
        handle_binding_response(socket, src_ip, src_port, msg, state)

      other ->
        Logger.warn("Unknown msg: #{inspect(other)}")
        state
    end
  end

  defp handle_binding_request(socket, src_ip, src_port, msg, state) do
    %Candidate{} = local_cand = find_cand(state.local_cands, socket)
    # username = state.local_ufrag <> ":" <> state.remote_ufrag
    # TODO handle error and check username
    {:ok, key} = Message.authenticate_st(msg, state.local_pwd)
    true = Message.check_fingerprint(msg)
    use_candidate = Message.get_attribute(msg, UseCandidate)

    type = %Type{class: :success_response, method: :binding}

    resp =
      Message.new(msg.transaction_id, type, [%XORMappedAddress{address: src_ip, port: src_port}])
      |> Message.with_integrity(key)
      |> Message.with_fingerprint()
      |> Message.encode()

    do_send(socket, {src_ip, src_port}, resp)

    {remote_cand, state} =
      case find_cand(state.remote_cands, src_ip, src_port) do
        nil ->
          # TODO what about priority
          cand = Candidate.new(:prflx, src_ip, src_port, nil, nil, nil)
          Logger.debug("Adding new peer reflexive candidate: #{inspect(cand)}")
          state = %{state | remote_cands: [cand | state.remote_cands]}
          {cand, state}

        %Candidate{} = cand ->
          {cand, state}
      end

    pair = CandidatePair.new(local_cand, remote_cand, state.role, :waiting)

    # TODO use triggered check queue
    case find_pair_with_index(state.checklist, pair) do
      nil ->
        if use_candidate do
          Logger.debug(
            "Adding new candidate pair that will be nominated after successfull conn check: #{inspect(pair)}"
          )

          pair = %CandidatePair{pair | nominate?: true}
          %{state | checklist: [pair | state.checklist]}
        else
          Logger.debug("Adding new candidate pair: #{inspect(pair)}")
          %{state | checklist: [pair | state.checklist]}
        end

      {%CandidatePair{} = pair, idx} ->
        if use_candidate do
          if pair.state == :succeeded do
            # TODO should we call this selected or nominated pair
            Logger.debug("Nomination request on valid pair. Selecting pair: #{inspect(pair)}")
            pair = %CandidatePair{pair | nominated?: true}
            state = %{state | selected_pair: pair}
            send(state.controlling_process, {self(), {:selected_pair, pair}})
            update_in(state.checklist, &List.update_at(&1, idx, fn -> pair end))
          else
            # TODO should we check if this pair is not in failed?
            Logger.debug("""
            Nomination request on pair that hasn't been verified yet.
            We will nominate pair once conn check passes.
            Pair: #{inspect(pair)}
            """)

            pair = %CandidatePair{pair | nominate?: true}
            update_in(state.checklist, &List.update_at(&1, idx, fn -> pair end))
          end
        else
          state
        end
    end
  end

  defp handle_binding_response(_socket, _src_ip, _src_port, msg, state)
       when is_map_key(state.gathering_transactions, msg.transaction_id) do
    t = Map.fetch!(state.gathering_transactions, msg.transaction_id)

    {:ok, %XORMappedAddress{address: address, port: port}} =
      Message.get_attribute(msg, XORMappedAddress)

    c =
      Candidate.new(
        :srflx,
        address,
        port,
        t.host_cand.address,
        t.host_cand.port,
        t.host_cand.socket
      )

    Logger.debug("New srflx candidate: #{inspect(c)}")

    send(state.controlling_process, {self(), {:new_candidate, Candidate.marshal(c)}})

    # TODO we should create pairs

    state
    |> update_in([:local_cands], fn local_cands -> [c | local_cands] end)
    |> update_in([:gathering_transactions, t.t_id], fn t -> %{t | state: :complete} end)
  end

  defp handle_binding_response(socket, src_ip, src_port, msg, state)
       when is_map_key(state.conn_checks, msg.transaction_id) do
    {%CandidatePair{} = pair, state} = pop_in(state, [:conn_checks, msg.transaction_id])

    {^pair, idx} = find_pair_with_index(state.checklist, pair)

    {:ok, {socket_ip, socket_port}} = :inet.sockname(socket)

    # check that the source and destination transport
    # adresses are symmetric
    if {src_ip, src_port} == {pair.remote_cand.address, pair.remote_cand.port} and
         socket == pair.local_cand.socket do
      if pair.nominate? do
        pair = %CandidatePair{pair | state: :succeeded, nominate?: false, nominated?: true}
        state = update_in(state, [:checklist], &List.update_at(&1, idx, fn _ -> pair end))
        Logger.debug("Nomination succeeded. Selecting pair: #{inspect(pair)}")
        send(state.controlling_process, {self(), {:selected_pair, pair}})
        %{state | selected_pair: pair}
      else
        # TODO use XORMappedAddress
        pair = %CandidatePair{pair | state: :succeeded}
        state = update_in(state, [:checklist], &List.update_at(&1, idx, fn _ -> pair end))
        Logger.debug("New valid pair: #{inspect(pair)}")
        send(state.controlling_process, {self(), :connected})
        %{state | valid_pairs: [pair | state.valid_pairs]}
      end
    else
      Logger.warn("""
      Ignoring conn check response, non-symmetric src and dst addresses.
      Sent from: #{inspect({pair.local_cand.base_address, pair.local_cand.base_port})}, to: #{inspect({pair.remote_cand.address, pair.remote_cand.port})}
      Recv from: #{inspect({src_ip, src_port})}, on: #{inspect({socket_ip, socket_port})}
      """)

      pair = %CandidatePair{pair | state: :failed}
      update_in(state, [:checklist], &List.update_at(&1, idx, fn _ -> pair end))
    end
  end

  defp handle_binding_response(socket, src_ip, src_port, msg, state) do
    # TODO should we have remote cand
    # to log it instead of src ip and port?
    %Candidate{} = local_cand = find_cand(state.local_cands, socket)

    Logger.warn("""
    Ignoring conn check response with unknown tid: #{msg.transaction_id},
    local_cand: #{inspect(local_cand)},
    src: #{inspect(src_ip)}:#{src_port}"
    """)

    state
  end

  defp do_gather_candidates(state) do
    {:ok, host_candidates} = Gatherer.gather_host_candidates(state.ip_filter)

    for cand <- host_candidates do
      send(state.controlling_process, {self(), {:new_candidate, Candidate.marshal(cand)}})
    end

    # TODO should we override?
    state = %{state | local_cands: state.local_cands ++ host_candidates}

    gathering_transactions =
      for stun_server <- state.stun_servers, host_cand <- host_candidates, into: %{} do
        <<t_id::12*8>> = :crypto.strong_rand_bytes(12)

        t = %{
          t_id: t_id,
          host_cand: host_cand,
          stun_server: stun_server,
          state: :waiting
        }

        {t_id, t}
      end

    if gathering_transactions == %{} do
      send(state.controlling_process, {self(), :gathering_complete})
      %{state | gathering_state: :complete}
    else
      %{state | gathering_transactions: gathering_transactions, gathering_state: :gathering}
    end
  end

  defp find_pair_with_index(pairs, pair) do
    find_pair_with_index(pairs, pair.local_cand, pair.remote_cand)
  end

  defp find_pair_with_index(pairs, local_cand, remote_cand) do
    # TODO which pairs are actually the same?
    pairs
    |> Enum.with_index()
    |> Enum.find(fn {p, _idx} ->
      p.local_cand.base_address == local_cand.base_address and
        p.local_cand.base_port == local_cand.base_port and
        p.local_cand.address == local_cand.address and
        p.local_cand.port == local_cand.port and
        p.remote_cand.address == remote_cand.address and
        p.remote_cand.port == remote_cand.port
    end)
  end

  defp find_cand(cands, ip, port) do
    Enum.find(cands, fn cand -> cand.address == ip and cand.port == port end)
  end

  defp find_cand(cands, socket) do
    Enum.find(cands, fn cand -> cand.socket == socket end)
  end

  defp send_conn_check(pair, state) do
    type = %Type{class: :request, method: :binding}

    # TODO setup correct tie_breakers
    role_attr =
      if state.role == :controlling do
        %ICEControlling{tie_breaker: 1}
      else
        %ICEControlled{tie_breaker: 2}
      end

    attrs = [
      %Username{value: "#{state.remote_ufrag}:#{state.local_ufrag}"},
      role_attr
    ]

    # we can nominate only when being the controlling agent
    # the controlled agent uses nominate? flag according to 7.3.1.5
    attrs =
      if pair.nominate? and state.role == :controlling do
        attrs ++ [%UseCandidate{}]
      else
        attrs
      end

    req =
      Message.new(type, attrs)
      |> Message.with_integrity(state.remote_pwd)
      |> Message.with_fingerprint()

    src = {pair.local_cand.base_address, pair.local_cand.base_port}
    dst = {pair.remote_cand.address, pair.remote_cand.port}

    do_send(pair.local_cand.socket, dst, Message.encode(req))

    pair = %CandidatePair{pair | state: :in_progress}

    state = put_in(state, [:conn_checks, req.transaction_id], pair)

    {pair, state}
  end

  defp do_send(socket, dst, data) do
    # FIXME that's a workaround for EPERM
    # retrying after getting EPERM seems to help
    case :gen_udp.send(socket, dst, data) do
      :ok ->
        :ok

      err ->
        Logger.error("UDP send error: #{inspect(err)}. Retrying...")
        do_send(socket, dst, data)
    end
  end
end
