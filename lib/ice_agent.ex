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

  @type opts() :: [
          ip_filter: (:inet.ip_address() -> boolean),
          stun_servers: [String.t()]
        ]

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
            Logger.warn("""
            Couldn't parse STUN server URI: #{inspect(stun_server)}. \
            Ignoring.\
            """)

            nil
        end
      end)
      |> Enum.reject(&(&1 == nil))

    {local_ufrag, local_pwd} = generate_credentials()

    Logger.debug("Starting Ta timer")
    ta_timer = Process.send_after(self(), :ta_timeout, @ta_timeout)

    state = %{
      state: :new,
      ta_timer: ta_timer,
      controlling_process: Keyword.fetch!(opts, :controlling_process),
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
    Logger.warn("Passed the same remote credentials to be set. Ignoring.")
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
    Logger.warn("Can't gather candidates. Gathering already in progress. Ignoring.")
    {:noreply, state}
  end

  @impl true
  def handle_cast(:gather_candidates, %{gathering_state: :complete} = state) do
    Logger.warn("Can't gather candidates. ICE restart needed. Ignoring.")
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

    {:noreply, state}
  end

  @impl true
  def handle_cast({:add_remote_candidate, _remote_cand}, %{eoc: true} = state) do
    Logger.warn("Received remote candidate after end-of-candidates. Ignoring.")
    {:noreply, state}
  end

  @impl true
  def handle_cast({:add_remote_candidate, remote_cand}, state) do
    Logger.debug("New remote candidate: #{inspect(remote_cand)}")

    case Candidate.unmarshal(remote_cand) do
      {:ok, remote_cand} ->
        state = do_add_remote_candidate(remote_cand, state)
        Logger.debug("Successfully added remote candidate.")
        {:noreply, state}

      {:error, reason} ->
        Logger.warn("Invalid remote candidate, reason: #{inspect(reason)}. Ignoring.")
        {:noreply, state}
    end
  end

  @impl true
  def handle_cast(:end_of_candidates, state) do
    {:noreply, %{state | eoc: true}}
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
    Logger.warn("""
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
    ta_timer = Process.send_after(self(), :ta_timeout, @ta_timeout)
    state = %{state | ta_timer: ta_timer}
    {:noreply, state}
  end

  @impl true
  def handle_info(:ta_timeout, state) do
    state = timeout_pending_transactions(state)

    state =
      case get_next_gathering_transaction(state.gathering_transactions) do
        {_t_id, transaction} -> handle_gathering_transaction(transaction, state)
        nil -> handle_checklist(state)
      end

    state =
      if state.state in [:completed, :failed] do
        Logger.debug("Stoping Ta timer")
        Process.cancel_timer(state.ta_timer)
        %{state | ta_timer: nil}
      else
        ta_timer = Process.send_after(self(), :ta_timeout, @ta_timeout)
        %{state | ta_timer: ta_timer}
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
      send(state.controlling_process, {:ex_ice, self(), {:data, packet}})
      {:noreply, state}
    end
  end

  @impl true
  def handle_info(msg, state) do
    Logger.warn("Got unexpected msg: #{inspect(msg)}")
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

    if added_pairs == [] do
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
        put_in(state, [:gathering_transactions, t_id], t)

      {:error, reason} ->
        Logger.debug("Couldn't send binding request, reason: #{reason}")

        state
        |> put_in([:gathering_transactions, t.t_id, :state], :failed)
        |> update_gathering_state()
    end
  end

  defp handle_checklist(state) do
    case Checklist.get_next_pair(state.checklist) do
      %CandidatePair{} = pair ->
        Logger.debug("Sending conn check on pair: #{inspect(pair.id)}")

        {pair, state} = send_conn_check(pair, state)

        put_in(state, [:checklist, pair.id], pair)

      nil ->
        if nominate?(state) do
          nominate(state)
        else
          state
        end
    end
  end

  defp timeout_pending_transactions(state) do
    now = System.monotonic_time(:millisecond)

    {stale_cc, cc} =
      Enum.split_with(state.conn_checks, fn {_id, %{send_time: send_time}} ->
        now - send_time >= @hto
      end)

    {stale_cc, cc} = {Map.new(stale_cc), Map.new(cc)}

    if stale_cc != %{} do
      stale_cc_ids = Enum.map(stale_cc, fn {id, _} -> id end)
      Logger.debug("Connectivity checks timed out: #{inspect(stale_cc_ids)}")
    end

    stale_pair_ids = Enum.map(stale_cc, fn {_id, %{pair_id: pair_id}} -> pair_id end)

    if stale_pair_ids != [] do
      Logger.debug("Pairs failed. Reason: timeout. Pairs: #{inspect(stale_pair_ids)}")
    end

    checklist = Checklist.timeout_pairs(state.checklist, stale_pair_ids)

    {stale_gath_trans, gath_trans} =
      Enum.split_with(state.gathering_transactions, fn {_id,
                                                        %{state: t_state, send_time: send_time}} ->
        t_state == :in_progress and now - send_time >= @hto
      end)

    gath_trans = Map.new(gath_trans)

    if stale_gath_trans != [] do
      Logger.debug("Gathering transactions timed out: #{inspect(stale_gath_trans)}")
    end

    %{state | checklist: checklist, conn_checks: cc, gathering_transactions: gath_trans}
    |> update_gathering_state()
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
        Logger.warn("""
        Ignoring binding response with unknown t_id: #{msg.transaction_id}.
        Is it retransmission or we called ICE restart?
        """)

        state

      other ->
        Logger.warn("""
        Unknown msg from: #{inspect({src_ip, src_port})}, on: #{inspect(socket_addr)}, msg: #{inspect(other)} \
        """)

        state
    end
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

      Logger.warn("""
      Ignoring conn check response, non-symmetric src and dst addresses.
      Sent from: #{inspect({conn_check_pair.local_cand.base_address, conn_check_pair.local_cand.base_port})}, \
      to: #{inspect({conn_check_pair.remote_cand.address, conn_check_pair.remote_cand.port})}
      Recv from: #{inspect({src_ip, src_port})}, on: #{inspect({socket_ip, socket_port})}
      """)

      conn_check_pair = %CandidatePair{conn_check_pair | state: :failed}

      put_in(state, [:checklist, conn_check_pair.id], conn_check_pair)
    end
  end

  defp handle_conn_check_success_response(conn_check_pair, msg, state) do
    case authenticate_msg(msg, state.remote_pwd) do
      {:ok, _key} ->
        @conn_check_handler[state.role].handle_conn_check_success_response(
          state,
          conn_check_pair,
          msg
        )

      {:error, reason} when reason in [:invalid_message_integrity, :invalid_fingerprint] ->
        Logger.debug("Ignoring conn check response, reason: #{reason}")

        conn_check_pair = %CandidatePair{conn_check_pair | state: :failed}

        put_in(state, [:checklist, conn_check_pair.id], conn_check_pair)
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

    send(state.controlling_process, {:ex_ice, self(), {:new_candidate, Candidate.marshal(c)}})

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

    if added_pairs == [] do
      Logger.debug("Not adding any new pairs as they were redundant")
    else
      Logger.debug("New candidate pairs: #{inspect(added_pairs)}")
    end

    state
    |> update_in([:local_cands], fn local_cands -> [c | local_cands] end)
    |> update_in([:gathering_transactions, t.t_id], fn t -> %{t | state: :complete} end)
    |> update_in([:checklist], fn _ -> checklist end)
    |> update_gathering_state()
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

  @doc false
  @spec get_or_create_local_cand(XORMappedAddress.t(), CandidatePair.t(), map()) :: Candidate.t()
  def get_or_create_local_cand(xor_addr, conn_check_pair, state) do
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

  defp nominate?(state) do
    # if we know there won't be further candidates,
    # there are no checks waiting or in-progress,
    # and we are the controlling agent, then we can nominate
    waiting = Checklist.waiting?(state.checklist)
    in_progress = Checklist.in_progress?(state.checklist)

    state.gathering_state == :complete and
      state.eoc and
      not (waiting or in_progress) and
      state.role == :controlling
  end

  defp nominate(state) do
    case Checklist.get_pair_for_nomination(state.checklist) do
      %CandidatePair{} = pair ->
        Logger.debug("Enqueuing pair for nomination: #{inspect(pair.id)}")

        pair = %CandidatePair{pair | state: :waiting, nominate?: true}
        # TODO use triggered check queue
        state = put_in(state, [:checklist, pair.id], pair)

        handle_checklist(state)

      nil ->
        # TODO revisit this
        # should we check if state.state == :in_progress?
        Logger.debug("No pairs for nomination. ICE failed.")
        send(state.controlling_process, {:ex_ice, self(), :failed})
        %{state | state: :failed}
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
    state =
      if state.ta_timer do
        Logger.debug("Stoping Ta timer")
        Process.cancel_timer(state.ta_timer)
        # flush mailbox
        receive do
          :ta_timeout -> :ok
        after
          0 -> :ok
        end

        %{state | ta_timer: nil}
      else
        state
      end

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

    if new_ice_state != state.state do
      send(state.controlling_process, {:ex_ice, self(), new_ice_state})
    end

    Logger.debug("Gathering state change: #{state.gathering_state} -> new")
    send(state.controlling_process, {:ex_ice, self(), {:gathering_state_change, :new}})

    Logger.debug("Starting Ta timer")
    ta_timer = Process.send_after(self(), :ta_timeout, @ta_timeout)

    %{
      state
      | state: new_ice_state,
        ta_timer: ta_timer,
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
        eoc: false
    }
  end

  @doc false
  @spec find_cand([Candidate.t()], :inet.ip_address(), :inet.port()) :: Candidate.t()
  def find_cand(cands, ip, port) do
    Enum.find(cands, fn cand -> cand.address == ip and cand.port == port end)
  end

  defp find_host_cand(cands, socket) do
    # this function returns only host candidates
    Enum.find(cands, fn cand -> cand.socket == socket and cand.type == :host end)
  end

  @doc false
  @spec generate_tiebreaker() :: integer()
  def generate_tiebreaker() do
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
         true <- Message.check_fingerprint(msg) do
      {:ok, key}
    else
      :error -> {:error, :invalid_message_integrity}
      false -> {:error, :invalid_fingerprint}
    end
  end

  defp send_conn_check(pair, state) do
    type = %Type{class: :request, method: :binding}

    # TODO setup correct tiebreakers
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
