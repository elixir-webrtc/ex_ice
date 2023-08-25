defmodule ExICE.ICEAgent do
  @moduledoc """
  ICE Agent.

  Not to be confused with Elixir Agent.
  """
  use GenServer

  require Logger

  alias ExICE.{
    Candidate,
    CandidatePair,
    Checklist,
    ControlledHandler,
    ControllingHandler,
    Gatherer
  }

  alias ExICE.Attribute.{ICEControlling, ICEControlled, Priority, UseCandidate}

  alias ExSTUN.Message
  alias ExSTUN.Message.Type
  alias ExSTUN.Message.Attribute.{ErrorCode, Username, XORMappedAddress}

  # Ta timeout in ms
  @ta_timeout 50

  # transaction timeout in ms
  # see appendix B.1
  @hto 500

  @conn_check_handler %{controlling: ControllingHandler, controlled: ControlledHandler}

  @type role() :: :controlling | :controlled

  @typedoc """
  Emitted when gathering process state has changed.

  For exact meaning refer to the W3C WebRTC standard, sec 5.6.3.
  """
  @type gathering_state_changed() :: {:gathering_state_change, :new | :gathering | :complete}

  @typedoc """
  Emitted when connection state has changed.

  For exact meaning refer to the W3C WebRTC standard, sec. 5.6.4.
  """
  @type connection_state_changed() :: :checking | :connected | :completed | :failed

  @typedoc """
  Messages sent by the ExICE.
  """
  @type signal() ::
          {:ex_ice, pid(),
           gathering_state_changed()
           | connection_state_changed
           | {:data, binary()}
           | {:new_candidate, binary()}}

  @typedoc """
  ICE Agent configuration options.

  * `ip_filter` - filter applied when gathering local candidates
  * `stun_servers` - list of STUN servers

  Currently, there is no support for local relay (TURN) candidates
  however, remote relay candidates work correctly.
  """
  @type opts() :: [
          ip_filter: (:inet.ip_address() -> boolean),
          stun_servers: [String.t()]
        ]

  defguard are_pairs_equal(p1, p2)
           when p1.local_cand.base_address == p2.local_cand.base_address and
                  p1.local_cand.base_port == p2.local_cand.base_port and
                  p1.local_cand.address == p2.local_cand.address and
                  p1.local_cand.port == p2.local_cand.port and
                  p1.remote_cand.address == p2.remote_cand.address and
                  p1.remote_cand.port == p2.remote_cand.port

  defguard is_response(class) when class in [:success_response, :error_response]

  @spec start_link(role(), opts()) :: GenServer.on_start()
  def start_link(role, opts \\ []) do
    GenServer.start_link(__MODULE__, opts ++ [role: role, controlling_process: self()])
  end

  @spec get_local_credentials(pid()) :: {:ok, ufrag :: binary(), pwd :: binary()}
  def get_local_credentials(ice_agent) do
    GenServer.call(ice_agent, :get_local_credentials)
  end

  @spec set_remote_credentials(pid(), binary(), binary()) :: :ok
  def set_remote_credentials(ice_agent, ufrag, passwd)
      when is_binary(ufrag) and is_binary(passwd) do
    GenServer.cast(ice_agent, {:set_remote_credentials, ufrag, passwd})
  end

  @spec gather_candidates(pid()) :: :ok
  def gather_candidates(ice_agent) do
    GenServer.cast(ice_agent, :gather_candidates)
  end

  @spec add_remote_candidate(pid(), String.t()) :: :ok
  def add_remote_candidate(ice_agent, candidate) when is_binary(candidate) do
    GenServer.cast(ice_agent, {:add_remote_candidate, candidate})
  end

  @spec end_of_candidates(pid()) :: :ok
  def end_of_candidates(ice_agent) do
    GenServer.cast(ice_agent, :end_of_candidates)
  end

  @spec send_data(pid(), binary()) :: :ok
  def send_data(ice_agent, data) when is_binary(data) do
    GenServer.cast(ice_agent, {:send_data, data})
  end

  @spec restart(pid()) :: :ok
  def restart(ice_agent) do
    GenServer.cast(ice_agent, :restart)
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
            Logger.warning("""
            Couldn't parse STUN server URI: #{inspect(stun_server)}. \
            Ignoring.\
            """)

            nil
        end
      end)
      |> Enum.reject(&(&1 == nil))

    {local_ufrag, local_pwd} = generate_credentials()

    state = %{
      state: :new,
      controlling_process: Keyword.fetch!(opts, :controlling_process),
      ta_timer: nil,
      gathering_transactions: %{},
      ip_filter: opts[:ip_filter],
      role: Keyword.fetch!(opts, :role),
      tiebreaker: generate_tiebreaker(),
      checklist: %{},
      selected_pair: nil,
      prev_selected_pair: nil,
      prev_valid_pairs: [],
      conn_checks: %{},
      gathering_state: :new,
      eoc: false,
      # {did we nominate pair, pair id}
      nominating?: {false, nil},
      local_ufrag: local_ufrag,
      local_pwd: local_pwd,
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
  def handle_call(:get_local_credentials, _from, state) do
    {:reply, {:ok, state.local_ufrag, state.local_pwd}, state}
  end

  @impl true
  def handle_cast(
        {:set_remote_credentials, ufrag, pwd},
        %{remote_ufrag: nil, remote_pwd: nil} = state
      ) do
    Logger.debug("Setting remote credentials: #{inspect(ufrag)}:#{inspect(pwd)}")
    state = %{state | remote_ufrag: ufrag, remote_pwd: pwd}
    {:noreply, state}
  end

  @impl true
  def handle_cast(
        {:set_remote_credentials, ufrag, pwd},
        %{remote_ufrag: ufrag, remote_pwd: pwd} = state
      ) do
    Logger.warning("Passed the same remote credentials to be set. Ignoring.")
    {:noreply, state}
  end

  @impl true
  def handle_cast({:set_remote_credentials, ufrag, pwd}, state) do
    Logger.debug("New remote credentials different than the current ones. Restarting ICE")
    state = do_restart(state)
    state = %{state | remote_ufrag: ufrag, remote_pwd: pwd}
    {:noreply, state}
  end

  @impl true
  def handle_cast(:gather_candidates, %{gathering_state: :gathering} = state) do
    Logger.warning("Can't gather candidates. Gathering already in progress. Ignoring.")
    {:noreply, state}
  end

  @impl true
  def handle_cast(:gather_candidates, %{gathering_state: :complete} = state) do
    Logger.warning("Can't gather candidates. ICE restart needed. Ignoring.")
    {:noreply, state}
  end

  @impl true
  def handle_cast(:gather_candidates, %{gathering_state: :new} = state) do
    Logger.debug("Gathering state change: #{state.gathering_state} -> gathering")
    send(state.controlling_process, {:ex_ice, self(), {:gathering_state_change, :gathering}})
    state = %{state | gathering_state: :gathering}

    {:ok, host_candidates} = Gatherer.gather_host_candidates(ip_filter: state.ip_filter)

    for cand <- host_candidates do
      send(
        state.controlling_process,
        {:ex_ice, self(), {:new_candidate, Candidate.marshal(cand)}}
      )
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
          send_time: nil,
          state: :waiting
        }

        {t_id, t}
      end

    state =
      %{state | gathering_transactions: gathering_transactions}
      |> update_gathering_state()
      |> update_ta_timer()

    {:noreply, state}
  end

  @impl true
  def handle_cast({:add_remote_candidate, _remote_cand}, %{eoc: true} = state) do
    Logger.warning("Received remote candidate after end-of-candidates. Ignoring.")
    {:noreply, state}
  end

  @impl true
  def handle_cast({:add_remote_candidate, remote_cand}, state) do
    Logger.debug("New remote candidate: #{inspect(remote_cand)}")

    case Candidate.unmarshal(remote_cand) do
      {:ok, remote_cand} ->
        state = do_add_remote_candidate(remote_cand, state)
        Logger.debug("Successfully added remote candidate.")
        state = update_connection_state(state)
        state = update_ta_timer(state)
        {:noreply, state}

      {:error, reason} ->
        Logger.warning("Invalid remote candidate, reason: #{inspect(reason)}. Ignoring.")
        {:noreply, state}
    end
  end

  @impl true
  def handle_cast(:end_of_candidates, %{role: :controlled} = state) do
    state = %{state | eoc: true}
    # we might need to move to the completed state
    state = update_connection_state(state)
    {:noreply, state}
  end

  @impl true
  def handle_cast(:end_of_candidates, %{role: :controlling} = state) do
    state = %{state | eoc: true}
    # check wheter it's time to nominate and if yes, try noimnate
    state = maybe_nominate(state)
    {:noreply, state}
  end

  @impl true
  def handle_cast({:send_data, data}, %{state: ice_state} = state)
      when ice_state in [:connected, :completed] do
    %CandidatePair{} =
      pair =
      state.selected_pair ||
        Checklist.get_valid_pair(state.checklist) ||
        state.prev_selected_pair ||
        List.first(state.prev_valid_pairs)

    dst = {pair.remote_cand.address, pair.remote_cand.port}
    do_send(pair.local_cand.socket, dst, data)
    {:noreply, state}
  end

  @impl true
  def handle_cast({:send_data, _data}, %{state: ice_state} = state) do
    Logger.warning("""
    Cannot send data in ICE state: #{inspect(ice_state)}. \
    Data can only be sent in state :connected or :completed. Ignoring.\
    """)

    {:noreply, state}
  end

  @impl true
  def handle_cast(:restart, state) do
    Logger.debug("Restarting ICE")
    state = do_restart(state)
    {:noreply, state}
  end

  @impl true
  def handle_info(:ta_timeout, %{remote_ufrag: nil, remote_pwd: nil} = state) do
    # TODO we can do this better i.e.
    # allow for executing gathering transactions
    Logger.debug("Ta timer fired but there are no remote credentials. Scheduling next check")
    ta_timer = Process.send_after(self(), :ta_timeout, @ta_timeout)
    state = %{state | ta_timer: ta_timer}
    state = update_ta_timer(state)
    {:noreply, state}
  end

  @impl true
  def handle_info(:ta_timeout, state) when state.state in [:completed, :failed] do
    Logger.warning("""
    Ta timer fired in unexpected state: #{state.state}.
    Trying to update gathering and connection states.
    """)

    state =
      state
      |> update_gathering_state()
      |> update_connection_state()
      |> update_ta_timer()

    {:noreply, state}
  end

  @impl true
  def handle_info(:ta_timeout, state) do
    state =
      state
      |> timeout_pending_transactions()
      |> update_gathering_state()
      |> update_connection_state()
      |> maybe_nominate()

    if state.state in [:completed, :failed] do
      state = update_ta_timer(state)
      {:noreply, state}
    else
      {transaction_executed, state} =
        case Checklist.get_next_pair(state.checklist) do
          %CandidatePair{} = pair ->
            Logger.debug("Sending conn check on pair: #{inspect(pair.id)}")
            {pair, state} = send_conn_check(pair, state)
            state = put_in(state, [:checklist, pair.id], pair)
            {true, state}

          nil ->
            case get_next_gathering_transaction(state.gathering_transactions) do
              {_t_id, transaction} ->
                case handle_gathering_transaction(transaction, state) do
                  {:ok, state} -> {true, state}
                  {:error, state} -> {false, state}
                end

              nil ->
                {false, state}
            end
        end

      unless transaction_executed do
        Logger.debug("Couldn't find transaction to execute. Did Ta timer fired without the need?")
      end

      # schedule next check and call update_ta_timer
      # if the next check is not needed, update_ta_timer will
      # cancel it
      ta_timer = Process.send_after(self(), :ta_timeout, @ta_timeout)
      state = %{state | ta_timer: ta_timer}
      state = update_ta_timer(state)

      {:noreply, state}
    end
  end

  @impl true
  def handle_info({:udp, socket, src_ip, src_port, packet}, state) do
    if ExSTUN.is_stun(packet) do
      case ExSTUN.Message.decode(packet) do
        {:ok, msg} ->
          state = handle_stun_msg(socket, src_ip, src_port, msg, state)
          {:noreply, state}

        {:error, reason} ->
          Logger.warning("Couldn't decode stun message: #{inspect(reason)}")
          {:noreply, state}
      end
    else
      send(state.controlling_process, {:ex_ice, self(), {:data, packet}})
      {:noreply, state}
    end
  end

  @impl true
  def handle_info(msg, state) do
    Logger.warning("Got unexpected msg: #{inspect(msg)}")
    {:noreply, state}
  end

  defp do_add_remote_candidate(remote_cand, state) do
    local_cands = get_matching_candidates(state.local_cands, remote_cand)

    checklist_foundations = Checklist.get_foundations(state.checklist)

    new_pairs =
      for local_cand <- local_cands, into: %{} do
        local_cand =
          if local_cand.type == :srflx do
            %Candidate{local_cand | address: local_cand.base_address, port: local_cand.base_port}
          else
            local_cand
          end

        pair_state = get_pair_state(local_cand, remote_cand, checklist_foundations)
        pair = CandidatePair.new(local_cand, remote_cand, state.role, pair_state)
        {pair.id, pair}
      end

    checklist = Checklist.prune(Map.merge(state.checklist, new_pairs))

    added_pairs = Map.drop(checklist, Map.keys(state.checklist))

    if added_pairs == %{} do
      Logger.debug("Not adding any new pairs as they were redundant")
    else
      Logger.debug("New candidate pairs: #{inspect(added_pairs)}")
    end

    %{state | checklist: checklist, remote_cands: [remote_cand | state.remote_cands]}
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

    case Gatherer.gather_srflx_candidate(t_id, host_cand, stun_server) do
      :ok ->
        now = System.monotonic_time(:millisecond)
        t = %{t | state: :in_progress, send_time: now}
        state = put_in(state, [:gathering_transactions, t_id], t)
        {:ok, state}

      {:error, reason} ->
        Logger.debug("Couldn't send binding request, reason: #{reason}")

        state =
          state
          |> put_in([:gathering_transactions, t.t_id, :state], :failed)
          |> update_gathering_state()

        {:error, state}
    end
  end

  defp timeout_pending_transactions(state) do
    now = System.monotonic_time(:millisecond)
    state = timeout_gathering_transactions(now, state)
    timeout_conn_checks(now, state)
  end

  defp timeout_conn_checks(now, state) do
    {stale_cc, cc} =
      Enum.split_with(state.conn_checks, fn {_id, %{send_time: send_time}} ->
        now - send_time >= @hto
      end)

    {stale_cc, cc} = {Map.new(stale_cc), Map.new(cc)}

    checklist =
      if stale_cc != %{} do
        Logger.debug("Connectivity checks timed out: #{inspect(Map.keys(stale_cc))}")
        stale_pair_ids = Enum.map(stale_cc, fn {_id, %{pair_id: pair_id}} -> pair_id end)
        Logger.debug("Pairs failed. Reason: timeout. Pairs: #{inspect(stale_pair_ids)}")
        Checklist.timeout_pairs(state.checklist, stale_pair_ids)
      else
        state.checklist
      end

    %{state | checklist: checklist, conn_checks: cc}
  end

  defp timeout_gathering_transactions(now, state) do
    {stale_gath_trans, gath_trans} =
      Enum.split_with(state.gathering_transactions, fn {_id,
                                                        %{state: t_state, send_time: send_time}} ->
        t_state == :in_progress and now - send_time >= @hto
      end)

    gath_trans = Map.new(gath_trans)

    if stale_gath_trans != [] do
      Logger.debug("Gathering transactions timed out: #{inspect(Keyword.keys(stale_gath_trans))}")
    end

    %{state | gathering_transactions: gath_trans}
  end

  defp handle_stun_msg(socket, src_ip, src_port, %Message{} = msg, state) do
    # TODO revisit 7.3.1.4

    {:ok, socket_addr} = :inet.sockname(socket)

    case msg.type do
      %Type{class: :request, method: :binding} ->
        Logger.debug("""
        Received binding request from: #{inspect({src_ip, src_port})}, on: #{inspect(socket_addr)} \
        """)

        handle_binding_request(socket, src_ip, src_port, msg, state)

      %Type{class: class, method: :binding}
      when is_response(class) and is_map_key(state.conn_checks, msg.transaction_id) ->
        Logger.debug("""
        Received conn check response from: #{inspect({src_ip, src_port})}, on: #{inspect(socket_addr)} \
        """)

        handle_conn_check_response(socket, src_ip, src_port, msg, state)

      %Type{class: class, method: :binding}
      when is_response(class) and is_map_key(state.gathering_transactions, msg.transaction_id) ->
        Logger.debug("""
        Received gathering transaction response from: #{inspect({src_ip, src_port})}, on: #{inspect(socket_addr)} \
        """)

        handle_gathering_transaction_response(socket, src_ip, src_port, msg, state)

      %Type{class: class, method: :binding} when is_response(class) ->
        Logger.warning("""
        Ignoring binding response with unknown t_id: #{msg.transaction_id}.
        Is it retransmission or we called ICE restart?
        """)

        state

      other ->
        Logger.warning("""
        Unknown msg from: #{inspect({src_ip, src_port})}, on: #{inspect(socket_addr)}, msg: #{inspect(other)} \
        """)

        state
    end
    |> update_gathering_state()
    |> update_connection_state()
    |> maybe_nominate()
    |> update_ta_timer()
  end

  ## BINDING REQUEST HANDLING ##

  defp handle_binding_request(socket, src_ip, src_port, msg, state) do
    # username = state.local_ufrag <> ":" <> state.remote_ufrag
    # TODO check username
    with {:ok, key} <- authenticate_msg(msg, state.local_pwd),
         {:ok, prio_attr} <- get_prio_attribute(msg),
         {:ok, role_attr} <- get_role_attribute(msg),
         use_cand_attr when use_cand_attr in [nil, %UseCandidate{}] <-
           get_use_cand_attribute(msg),
         {{:ok, state}, _} <- {check_req_role_conflict(role_attr, state), key} do
      case find_host_cand(state.local_cands, socket) do
        nil ->
          # keepalive on pair selected before ice restart
          # TODO can we reach this? Won't we use incorrect local_pwd for auth?
          Logger.debug("Keepalive on pair from previous ICE session")
          send_binding_success_response(socket, src_ip, src_port, msg, key)
          state

        %Candidate{} = local_cand ->
          {remote_cand, state} = get_or_create_remote_cand(src_ip, src_port, prio_attr, state)
          pair = CandidatePair.new(local_cand, remote_cand, state.role, :waiting)

          @conn_check_handler[state.role].handle_conn_check_request(
            state,
            pair,
            msg,
            use_cand_attr,
            key
          )
      end
    else
      {:error, reason}
      when reason in [
             :invalid_priority_attribute,
             :no_priority_attribute,
             :invalid_use_candidate_attribute
           ] ->
        # TODO should we reply with 400 bad request when
        # attributes are invalid (they are present but invalid)
        # TODO should we authenticate?
        # chrome does not authenticate but section 6.3.1.1 suggests
        # we should add message-integrity
        Logger.debug("""
        Invalid binding request, reason: #{reason}. \
        Sending bad request error response"\
        """)

        send_bad_request_error_response(socket, src_ip, src_port, msg)
        state

      {:error, reason} ->
        Logger.debug("Ignoring binding request, reason: #{reason}")
        state

      {{:error, :role_conflict, tiebreaker}, key} ->
        Logger.debug("""
        Role conflict. We retain our role which is: #{state.role}. Sending error response.
        Our tiebreaker: #{state.tiebreaker}
        Peer's tiebreaker: #{tiebreaker}\
        """)

        send_role_conflict_error_response(socket, src_ip, src_port, msg, key)
        state
    end
  end

  defp get_prio_attribute(msg) do
    case Message.get_attribute(msg, Priority) do
      {:ok, _} = attr -> attr
      {:error, _} -> {:error, :invalid_priority_attribute}
      nil -> {:error, :no_priority_attribute}
    end
  end

  defp get_role_attribute(msg) do
    role_attr =
      Message.get_attribute(msg, ICEControlling) || Message.get_attribute(msg, ICEControlled)

    case role_attr do
      {:ok, _} -> role_attr
      {:error, _} -> {:error, :invalid_role_attribute}
      nil -> {:error, :no_role_attribute}
    end
  end

  defp get_use_cand_attribute(msg) do
    # this function breaks the convention...
    case Message.get_attribute(msg, UseCandidate) do
      {:ok, attr} -> attr
      {:error, _} -> {:error, :invalid_use_candidate_attribute}
      nil -> nil
    end
  end

  defp check_req_role_conflict(
         %ICEControlling{tiebreaker: tiebreaker},
         %{role: :controlling} = state
       )
       when state.tiebreaker >= tiebreaker do
    {:error, :role_conflict, tiebreaker}
  end

  defp check_req_role_conflict(
         %ICEControlling{tiebreaker: tiebreaker},
         %{role: :controlling} = state
       ) do
    Logger.debug("""
    Role conflict, switching our role to controlled. Recomputing pairs priority.
    Our tiebreaker: #{state.tiebreaker}
    Peer's tiebreaker: #{tiebreaker}\
    """)

    checklist = Checklist.recompute_pair_prios(state.checklist, :controlled)
    {:ok, %{state | role: :controlled, checklist: checklist}}
  end

  defp check_req_role_conflict(
         %ICEControlled{tiebreaker: tiebreaker},
         %{role: :controlled} = state
       )
       when state.tiebreaker >= tiebreaker do
    Logger.debug("""
    Role conflict, switching our role to controlling. Recomputing pairs priority.
    Our tiebreaker: #{state.tiebreaker}
    Peer's tiebreaker: #{tiebreaker}\
    """)

    checklist = Checklist.recompute_pair_prios(state.checklist, :controlling)
    {:ok, %{state | role: :controlling, checklist: checklist}}
  end

  defp check_req_role_conflict(%ICEControlled{tiebreaker: tiebreaker}, %{role: :controlled}) do
    {:error, :role_conflict, tiebreaker}
  end

  defp check_req_role_conflict(_role_attr, state), do: {:ok, state}

  ## BINDING RESPONSE HANDLING ##

  defp handle_conn_check_response(socket, src_ip, src_port, msg, state) do
    {%{pair_id: pair_id}, state} = pop_in(state, [:conn_checks, msg.transaction_id])
    conn_check_pair = Map.fetch!(state.checklist, pair_id)

    # check that the source and destination transport
    # adresses are symmetric - see sec. 7.2.5.2.1
    if is_symmetric(socket, {src_ip, src_port}, conn_check_pair) do
      case msg.type.class do
        :success_response -> handle_conn_check_success_response(conn_check_pair, msg, state)
        :error_response -> handle_conn_check_error_response(conn_check_pair, msg, state)
      end
    else
      {:ok, {socket_ip, socket_port}} = :inet.sockname(socket)

      Logger.warning("""
      Ignoring conn check response, non-symmetric src and dst addresses.
      Sent from: #{inspect({conn_check_pair.local_cand.base_address, conn_check_pair.local_cand.base_port})}, \
      to: #{inspect({conn_check_pair.remote_cand.address, conn_check_pair.remote_cand.port})}
      Recv from: #{inspect({src_ip, src_port})}, on: #{inspect({socket_ip, socket_port})}
      Pair failed: #{conn_check_pair.id}
      """)

      conn_check_pair = %CandidatePair{conn_check_pair | state: :failed}

      put_in(state, [:checklist, conn_check_pair.id], conn_check_pair)
    end
  end

  defp handle_conn_check_success_response(conn_check_pair, msg, state) do
    with {:ok, _key} <- authenticate_msg(msg, state.remote_pwd),
         {:ok, xor_addr} <- Message.get_attribute(msg, XORMappedAddress) do
      {local_cand, state} = get_or_create_local_cand(xor_addr, conn_check_pair, state)
      remote_cand = conn_check_pair.remote_cand

      valid_pair =
        CandidatePair.new(local_cand, remote_cand, state.role, :succeeded, valid?: true)

      checklist_pair = Checklist.find_pair(state.checklist, valid_pair)

      {pair_id, state} = add_valid_pair(valid_pair, conn_check_pair, checklist_pair, state)

      # get new conn check pair as it will have updated
      # discovered and succeeded pair fields
      conn_check_pair = Map.fetch!(state.checklist, conn_check_pair.id)
      nominate? = conn_check_pair.nominate?
      conn_check_pair = %CandidatePair{conn_check_pair | nominate?: false}
      state = put_in(state, [:checklist, conn_check_pair.id], conn_check_pair)
      @conn_check_handler[state.role].update_nominated_flag(state, pair_id, nominate?)
    else
      {:error, reason} when reason == :invalid_auth_attributes ->
        Logger.debug("Ignoring conn check response, reason: #{reason}")

        conn_check_pair = %CandidatePair{conn_check_pair | state: :failed}

        put_in(state, [:checklist, conn_check_pair.id], conn_check_pair)

      _other ->
        Logger.debug("""
        Invalid or no XORMappedAddress. Ignoring conn check response.
        Conn check tid: #{inspect(msg.transaction_id)},
        Conn check pair: #{inspect(conn_check_pair.id)}.
        """)

        state
    end
  end

  defp handle_conn_check_error_response(conn_check_pair, msg, state) do
    # TODO should we authenticate?
    # chrome seems not to add message integrity for 400 bad request errors
    # libnice seems to add message integrity for role conflict
    # RFC says we SHOULD add message integrity when possible
    case Message.get_attribute(msg, ErrorCode) do
      {:ok, %ErrorCode{code: 487}} ->
        new_role = if state.role == :controlling, do: :controlled, else: :controlling

        Logger.debug("""
        Conn check failed due to role conflict. Changing our role to: #{new_role}, \
        recomputing pair priorities, regenerating tiebreaker and rescheduling conn check \
        """)

        conn_check_pair = %CandidatePair{conn_check_pair | state: :waiting}
        checklist = Map.replace!(state.checklist, conn_check_pair.id, conn_check_pair)
        tiebreaker = generate_tiebreaker()
        %{state | role: new_role, checklist: checklist, tiebreaker: tiebreaker}

      other ->
        Logger.debug(
          "Conn check failed due to error resposne from the peer, error: #{inspect(other)}"
        )

        conn_check_pair = %CandidatePair{conn_check_pair | state: :failed}
        put_in(state, [:checklist, conn_check_pair.id], conn_check_pair)
    end
  end

  defp handle_gathering_transaction_response(socket, src_ip, src_port, msg, state) do
    case msg.type.class do
      :success_response ->
        handle_gathering_transaction_success_response(socket, src_ip, src_port, msg, state)

      :error_response ->
        handle_gathering_transaction_error_response(socket, src_ip, src_port, msg, state)
    end
  end

  defp handle_gathering_transaction_success_response(_socket, _src_ip, _src_port, msg, state) do
    t = Map.fetch!(state.gathering_transactions, msg.transaction_id)

    {:ok, %XORMappedAddress{address: xor_addr, port: xor_port}} =
      Message.get_attribute(msg, XORMappedAddress)

    case find_cand(state.local_cands, xor_addr, xor_port) do
      nil ->
        c =
          Candidate.new(
            :srflx,
            xor_addr,
            xor_port,
            t.host_cand.address,
            t.host_cand.port,
            t.host_cand.socket
          )

        Logger.debug("New srflx candidate: #{inspect(c)}")
        send(state.controlling_process, {:ex_ice, self(), {:new_candidate, Candidate.marshal(c)}})
        add_srflx_cand(c, state)

      cand ->
        Logger.debug("""
        Not adding srflx candidate as we already have a candidate with the same address.
        Candidate: #{inspect(cand)}
        """)
    end
    |> update_in([:gathering_transactions, t.t_id], fn t -> %{t | state: :complete} end)
  end

  defp handle_gathering_transaction_error_response(_socket, _src_ip, _src_port, msg, state) do
    t = Map.fetch!(state.gathering_transactions, msg.transaction_id)

    error_code =
      case Message.get_attribute(msg, ErrorCode) do
        {:ok, error_code} -> error_code
        _other -> nil
      end

    Logger.debug(
      "Gathering transaction failed, t_id: #{msg.transaction_id}, reason: #{inspect(error_code)}"
    )

    update_in(state, [:gathering_transactions, t.t_id], fn t -> %{t | state: :failed} end)
  end

  defp add_srflx_cand(c, state) do
    # replace address and port with candidate base
    # and prune the checklist - see sec. 6.1.2.4
    local_cand = %Candidate{c | address: c.base_address, port: c.base_port}

    remote_cands = get_matching_candidates(state.remote_cands, local_cand)

    checklist_foundations = Checklist.get_foundations(state.checklist)

    new_pairs =
      for remote_cand <- remote_cands, into: %{} do
        pair_state = get_pair_state(local_cand, remote_cand, checklist_foundations)
        pair = CandidatePair.new(local_cand, remote_cand, state.role, pair_state)
        {pair.id, pair}
      end

    checklist = Checklist.prune(Map.merge(state.checklist, new_pairs))

    added_pairs = Map.drop(checklist, Map.keys(state.checklist))

    if added_pairs == %{} do
      Logger.debug("Not adding any new pairs as they were redundant")
    else
      Logger.debug("New candidate pairs: #{inspect(added_pairs)}")
    end

    %{state | checklist: checklist, local_cands: [c | state.local_cands]}
  end

  # Adds valid pair according to sec 7.2.5.3.2
  # TODO sec. 7.2.5.3.3
  # The agent MUST set the states for all other Frozen candidate pairs in
  # all checklists with the same foundation to Waiting.
  #
  # Check against valid_pair == conn_check_pair before
  # checking against valid_pair == checklist_pair as
  # the second condition is always true if the first one is
  defp add_valid_pair(valid_pair, conn_check_pair, _, state)
       when are_pairs_equal(valid_pair, conn_check_pair) do
    Logger.debug("""
    New valid pair: #{conn_check_pair.id} \
    resulted from conn check on pair: #{conn_check_pair.id}\
    """)

    conn_check_pair = %CandidatePair{
      conn_check_pair
      | succeeded_pair_id: conn_check_pair.id,
        discovered_pair_id: conn_check_pair.id,
        state: :succeeded,
        valid?: true
    }

    checklist = Map.replace!(state.checklist, conn_check_pair.id, conn_check_pair)

    state = %{state | checklist: checklist}
    {conn_check_pair.id, state}
  end

  defp add_valid_pair(
         valid_pair,
         conn_check_pair,
         %CandidatePair{valid?: true} = checklist_pair,
         state
       )
       when are_pairs_equal(valid_pair, checklist_pair) do
    Logger.debug("""
    New valid pair: #{checklist_pair.id} \
    resulted from conn check on pair: #{conn_check_pair.id} \
    but there is already such a pair in the checklist marked as valid.
    Should this ever happen after we don't add redundant srflx candidates?
    Checklist pair: #{checklist_pair.id}.
    """)

    # if we get here, don't update discovered_pair_id and succeeded_pair_id of 
    # the checklist pair as they are already set
    conn_check_pair = %CandidatePair{
      conn_check_pair
      | state: :succeeded,
        succeeded_pair_id: conn_check_pair.id,
        discovered_pair_id: checklist_pair.id
    }

    checklist_pair = %CandidatePair{checklist_pair | state: :succeeded}

    checklist =
      state.checklist
      |> Map.replace!(checklist_pair.id, checklist_pair)
      |> Map.replace!(conn_check_pair.id, conn_check_pair)

    state = %{state | checklist: checklist}
    {checklist_pair.id, state}
  end

  defp add_valid_pair(valid_pair, conn_check_pair, checklist_pair, state)
       when are_pairs_equal(valid_pair, checklist_pair) do
    Logger.debug("""
    New valid pair: #{checklist_pair.id} \
    resulted from conn check on pair: #{conn_check_pair.id}\
    """)

    conn_check_pair = %CandidatePair{
      conn_check_pair
      | discovered_pair_id: checklist_pair.id,
        succeeded_pair_id: conn_check_pair.id,
        state: :succeeded
    }

    checklist_pair = %CandidatePair{
      checklist_pair
      | discovered_pair_id: checklist_pair.id,
        succeeded_pair_id: conn_check_pair.id,
        state: :succeeded,
        valid?: true
    }

    checklist =
      state.checklist
      |> Map.replace!(conn_check_pair.id, conn_check_pair)
      |> Map.replace!(checklist_pair.id, checklist_pair)

    state = %{state | checklist: checklist}
    {checklist_pair.id, state}
  end

  defp add_valid_pair(valid_pair, conn_check_pair, _, state) do
    # TODO compute priority according to sec 7.2.5.3.2
    Logger.debug("""
    Adding new candidate pair resulted from conn check \
    on pair: #{conn_check_pair.id}. Pair: #{inspect(valid_pair)}\
    """)

    Logger.debug("New valid pair: #{valid_pair.id}")

    conn_check_pair = %CandidatePair{
      conn_check_pair
      | discovered_pair_id: valid_pair.id,
        succeeded_pair_id: conn_check_pair.id,
        state: :succeeded
    }

    valid_pair = %CandidatePair{
      valid_pair
      | discovered_pair_id: valid_pair.id,
        succeeded_pair_id: conn_check_pair.id
    }

    checklist =
      state.checklist
      |> Map.replace!(conn_check_pair.id, conn_check_pair)
      |> Map.put(valid_pair.id, valid_pair)

    state = %{state | checklist: checklist}
    {valid_pair.id, state}
  end

  @doc false
  @spec send_binding_success_response(CandidatePair.t(), Message.t(), binary()) :: :ok
  def send_binding_success_response(pair, msg, key) do
    src_ip = pair.remote_cand.address
    src_port = pair.remote_cand.port
    send_binding_success_response(pair.local_cand.socket, src_ip, src_port, msg, key)
  end

  @doc false
  @spec send_bad_request_error_response(CandidatePair.t(), Message.t()) :: :ok
  def send_bad_request_error_response(pair, msg) do
    src_ip = pair.remote_cand.address
    src_port = pair.remote_cand.port
    send_bad_request_error_response(pair.local_cand.socket, src_ip, src_port, msg)
  end

  defp send_binding_success_response(socket, src_ip, src_port, req, key) do
    type = %Type{class: :success_response, method: :binding}

    resp =
      Message.new(req.transaction_id, type, [%XORMappedAddress{address: src_ip, port: src_port}])
      |> Message.with_integrity(key)
      |> Message.with_fingerprint()
      |> Message.encode()

    do_send(socket, {src_ip, src_port}, resp)
  end

  defp send_bad_request_error_response(socket, src_ip, src_port, req) do
    type = %Type{class: :error_response, method: :binding}

    response =
      Message.new(req.transaction_id, type, [%ErrorCode{code: 400}])
      |> Message.encode()

    do_send(socket, {src_ip, src_port}, response)
  end

  defp send_role_conflict_error_response(socket, src_ip, src_port, req, key) do
    type = %Type{class: :error_response, method: :binding}

    response =
      Message.new(req.transaction_id, type, [%ErrorCode{code: 487}])
      |> Message.with_integrity(key)
      |> Message.with_fingerprint()
      |> Message.encode()

    do_send(socket, {src_ip, src_port}, response)
  end

  defp get_matching_candidates(candidates, cand) do
    Enum.filter(candidates, &(Candidate.family(&1) == Candidate.family(cand)))
  end

  defp is_symmetric(socket, response_src, conn_check_pair) do
    request_dst = {conn_check_pair.remote_cand.address, conn_check_pair.remote_cand.port}
    response_src == request_dst and socket == conn_check_pair.local_cand.socket
  end

  defp get_pair_state(local_cand, remote_cand, checklist_foundations) do
    f = {local_cand.foundation, remote_cand.foundation}
    if f in checklist_foundations, do: :frozen, else: :waiting
  end

  defp get_or_create_local_cand(xor_addr, conn_check_pair, state) do
    local_cand = find_cand(state.local_cands, xor_addr.address, xor_addr.port)

    if local_cand do
      {local_cand, state}
    else
      # prflx candidate sec 7.2.5.3.1
      # TODO calculate correct prio and foundation
      cand =
        Candidate.new(
          :prflx,
          xor_addr.address,
          xor_addr.port,
          conn_check_pair.local_cand.base_address,
          conn_check_pair.local_cand.base_port,
          conn_check_pair.local_cand.socket
        )

      Logger.debug("Adding new local prflx candidate: #{inspect(cand)}")
      state = %{state | local_cands: [cand | state.local_cands]}
      {cand, state}
    end
  end

  defp get_or_create_remote_cand(src_ip, src_port, _prio_attr, state) do
    case find_cand(state.remote_cands, src_ip, src_port) do
      nil ->
        # TODO calculate correct prio using prio_attr
        cand = Candidate.new(:prflx, src_ip, src_port, nil, nil, nil)
        Logger.debug("Adding new remote prflx candidate: #{inspect(cand)}")
        state = %{state | remote_cands: [cand | state.remote_cands]}
        {cand, state}

      %Candidate{} = cand ->
        {cand, state}
    end
  end

  defp maybe_nominate(state) do
    if time_to_nominate?(state) do
      Logger.debug("Time to nominate a pair! Looking for a best valid pair...")
      try_nominate(state)
    else
      state
    end
  end

  defp time_to_nominate?(%{state: :completed}), do: false

  defp time_to_nominate?(state) do
    {nominating?, _} = state.nominating?
    # if we are not during nomination and we know there won't be further candidates,
    # there are no checks waiting or in-progress,
    # and we are the controlling agent, then we can nominate
    nominating? == false and state.gathering_state == :complete and
      state.eoc and
      Checklist.finished?(state.checklist) and
      state.role == :controlling
  end

  @doc false
  @spec try_nominate(map()) :: map()
  def try_nominate(state) do
    case Checklist.get_pair_for_nomination(state.checklist) do
      %CandidatePair{} = pair ->
        Logger.debug("Trying to nominate pair: #{inspect(pair.id)}")
        pair = %CandidatePair{pair | nominate?: true}
        state = put_in(state, [:checklist, pair.id], pair)
        state = %{state | nominating?: {true, pair.id}}
        pair = Map.fetch!(state.checklist, pair.succeeded_pair_id)
        pair = %CandidatePair{pair | state: :waiting, nominate?: true}
        {pair, state} = send_conn_check(pair, state)
        put_in(state, [:checklist, pair.id], pair)

      nil ->
        # TODO revisit this
        # should we check if state.state == :in_progress?
        Logger.debug("""
        No pairs for nomination. ICE failed. #{inspect(state.checklist, pretty: true)}
        """)

        change_connection_state(:failed, state)
    end
  end

  defp update_gathering_state(%{gathering_state: :complete} = state), do: state

  defp update_gathering_state(state) do
    transaction_in_progress? =
      Enum.any?(state.gathering_transactions, fn {_id, %{state: t_state}} ->
        t_state in [:waiting, :in_progress]
      end)

    cond do
      state.gathering_state == :new and transaction_in_progress? ->
        Logger.debug("Gathering state change: new -> gathering")
        send(state.controlling_process, {:ex_ice, self(), {:gathering_state_change, :gathering}})
        %{state | gathering_state: :gathering}

      state.gathering_state == :gathering and not transaction_in_progress? ->
        Logger.debug("Gathering state change: gathering -> complete")
        send(state.controlling_process, {:ex_ice, self(), {:gathering_state_change, :complete}})
        %{state | gathering_state: :complete}

      true ->
        state
    end
  end

  defp do_restart(state) do
    valid_pairs = state.checklist |> Map.values() |> Enum.filter(fn pair -> pair.valid? end)
    valid_sockets = Enum.map(valid_pairs, fn p -> p.local_cand.socket end)

    {prev_selected_pair, prev_valid_pairs} =
      if valid_pairs == [] do
        {state.prev_selected_pair, state.prev_valid_pairs}
      else
        # TODO cleanup prev pairs
        {state.selected_pair, valid_pairs}
      end

    state.local_cands
    |> Enum.uniq_by(fn c -> c.socket end)
    |> Enum.each(fn c ->
      if c.socket not in valid_sockets do
        Logger.debug(
          "Closing local candidate's socket: #{inspect(c.base_address)}:#{c.base_port}"
        )

        :ok = :gen_udp.close(c.socket)
      end
    end)

    {ufrag, pwd} = generate_credentials()

    new_ice_state =
      cond do
        state.state in [:disconnected, :failed] -> :checking
        state.state == :completed -> :connected
        true -> state.state
      end

    state =
      if new_ice_state != state.state do
        change_connection_state(new_ice_state, state)
      else
        state
      end

    Logger.debug("Gathering state change: #{state.gathering_state} -> new")
    send(state.controlling_process, {:ex_ice, self(), {:gathering_state_change, :new}})

    %{
      state
      | state: new_ice_state,
        gathering_state: :new,
        gathering_transactions: %{},
        selected_pair: nil,
        prev_selected_pair: prev_selected_pair,
        prev_valid_pairs: prev_valid_pairs,
        conn_checks: %{},
        checklist: %{},
        local_cands: [],
        remote_cands: [],
        local_ufrag: ufrag,
        local_pwd: pwd,
        remote_ufrag: nil,
        remote_pwd: nil,
        eoc: false,
        nominating?: {false, nil}
    }
    |> update_ta_timer()
  end

  defp find_cand(cands, ip, port) do
    Enum.find(cands, fn cand -> cand.address == ip and cand.port == port end)
  end

  defp find_host_cand(cands, socket) do
    # this function returns only host candidates
    Enum.find(cands, fn cand -> cand.socket == socket and cand.type == :host end)
  end

  defp generate_tiebreaker() do
    <<tiebreaker::64>> = :crypto.strong_rand_bytes(8)
    tiebreaker
  end

  defp generate_credentials() do
    # TODO am I using Base.encode64 correctly?
    ufrag = :crypto.strong_rand_bytes(3) |> Base.encode64()
    pwd = :crypto.strong_rand_bytes(16) |> Base.encode64()
    {ufrag, pwd}
  end

  defp authenticate_msg(msg, local_pwd) do
    with {:ok, key} <- Message.authenticate_st(msg, local_pwd),
         :ok <- Message.check_fingerprint(msg) do
      {:ok, key}
    else
      {:error, _reason} -> {:error, :invalid_auth_attributes}
    end
  end

  @doc false
  @spec change_connection_state(atom(), map()) :: map()
  def change_connection_state(new_conn_state, state) do
    Logger.debug("Connection state change: #{state.state} -> #{new_conn_state}")
    send(state.controlling_process, {:ex_ice, self(), new_conn_state})
    %{state | state: new_conn_state}
  end

  defp update_connection_state(%{state: :new} = state) do
    if Checklist.waiting?(state.checklist) or Checklist.in_progress?(state.checklist) do
      change_connection_state(:checking, state)
    else
      state
    end
  end

  defp update_connection_state(%{state: :checking} = state) do
    cond do
      Checklist.get_valid_pair(state.checklist) != nil ->
        Logger.debug("Found a valid pair. Changing connection state to connected")
        change_connection_state(:connected, state)

      state.eoc == true and state.gathering_state == :complete and
          Checklist.finished?(state.checklist) ->
        Logger.debug("""
        Finished all conn checks, there won't be any further local or remote candidates
        and we don't have any valid or selected pair. Changing connection state to failed.
        """)

        change_connection_state(:failed, state)

      true ->
        state
    end
  end

  # credo:disable-for-next-line Credo.Check.Refactor.CyclomaticComplexity
  defp update_connection_state(%{state: :connected} = state) do
    cond do
      state.eoc == true and state.gathering_state == :complete and
        Checklist.get_valid_pair(state.checklist) == nil and
          Checklist.finished?(state.checklist) ->
        change_connection_state(:failed, state)

      # Assuming the controlling side uses regulard nomination,
      # the controlled side could move to the completed
      # state as soon as it receives nomination request (or after
      # successful triggered check caused by nomination request).
      # However, to be compatible with the older RFC's aggresive
      # nomination, we wait for the end-of-candidates indication
      # and checklist to be finished.
      # This also means, that if the other side never sets eoc,
      # we will never move to the completed state.
      # This seems to be compliant with libwebrtc.
      state.role == :controlled and state.eoc == true and state.gathering_state == :complete and
        state.selected_pair != nil and Checklist.finished?(state.checklist) ->
        Logger.debug("""
        Finished all conn checks, there won't be any further local or remote candidates
        and we have selected pair. Changing connection state to completed.
        """)

        change_connection_state(:completed, state)

      state.role == :controlling and state.selected_pair != nil ->
        change_connection_state(:completed, state)

      state.role == :controlling and match?({true, _pair_id}, state.nominating?) and
          Map.fetch!(state.checklist, elem(state.nominating?, 1)).state == :failed ->
        {_, pair_id} = state.nominating?

        Logger.debug("""
        Pair we tried to nominate failed. Changing connection state to failed. \
        Pair id: #{pair_id}
        """)

        change_connection_state(:failed, state)

      true ->
        state
    end
  end

  # TODO handle more states
  defp update_connection_state(state) do
    state
  end

  defp update_ta_timer(state) do
    if is_work_to_do(state) do
      if state.ta_timer != nil do
        # do nothing, timer already works
        state
      else
        Logger.debug("Starting Ta timer")
        enable_timer(state)
      end
    else
      if state.ta_timer != nil do
        Logger.debug("Stopping Ta timer")
        disable_timer(state)
      else
        # do nothing, timer already stopped
        state
      end
    end
  end

  defp is_work_to_do(state) when state.state in [:completed, :failed], do: false

  defp is_work_to_do(state) do
    gath_trans_in_progress? =
      Enum.any?(state.gathering_transactions, fn {_id, %{state: t_state}} ->
        t_state in [:waiting, :in_progress]
      end)

    not Checklist.finished?(state.checklist) or gath_trans_in_progress?
  end

  defp enable_timer(state) do
    timer = Process.send_after(self(), :ta_timeout, 0)
    %{state | ta_timer: timer}
  end

  defp disable_timer(state) do
    Process.cancel_timer(state.ta_timer)

    # flush mailbox
    receive do
      :ta_timeout -> :ok
    after
      0 -> :ok
    end

    %{state | ta_timer: nil}
  end

  @doc false
  @spec send_conn_check(CandidatePair.t(), map()) :: {CandidatePair.t(), map()}
  def send_conn_check(pair, state) do
    type = %Type{class: :request, method: :binding}

    role_attr =
      if state.role == :controlling do
        %ICEControlling{tiebreaker: state.tiebreaker}
      else
        %ICEControlled{tiebreaker: state.tiebreaker}
      end

    # priority sent to the other side has to be
    # computed with the candidate type preference of
    # peer-reflexive; refer to sec 7.1.1
    priority = Candidate.priority(:prflx)

    attrs = [
      %Username{value: "#{state.remote_ufrag}:#{state.local_ufrag}"},
      %Priority{priority: priority},
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

    dst = {pair.remote_cand.address, pair.remote_cand.port}

    do_send(pair.local_cand.socket, dst, Message.encode(req))

    pair = %CandidatePair{pair | state: :in_progress}

    conn_check = %{
      pair_id: pair.id,
      send_time: System.monotonic_time(:millisecond)
    }

    state = put_in(state, [:conn_checks, req.transaction_id], conn_check)

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

        case :gen_udp.send(socket, dst, data) do
          :ok ->
            Logger.debug("Successful retry")

          err ->
            Logger.error("Unseccessful retry: #{inspect(err)}. Giving up.")
        end
    end
  end
end
