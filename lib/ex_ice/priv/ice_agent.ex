defmodule ExICE.Priv.ICEAgent do
  @moduledoc false

  require Logger

  alias ExICE.Priv.IfDiscovery
  alias ExICE.Priv.{Candidate, CandidatePair, Checklist, ConnCheckHandler, Gatherer, Transport}
  alias ExICE.Priv.Attribute.{ICEControlling, ICEControlled, Priority, UseCandidate}

  alias ExSTUN.Message
  alias ExSTUN.Message.Type
  alias ExSTUN.Message.Attribute.{ErrorCode, Username, XORMappedAddress}

  # Ta timeout in ms
  @ta_timeout 50

  # transaction timeout in ms
  # see appendix B.1
  @hto 500

  @conn_check_handler %{
    controlling: ConnCheckHandler.Controlling,
    controlled: ConnCheckHandler.Controlled
  }

  defguardp are_pairs_equal(p1, p2)
            when p1.local_cand.base.base_address == p2.local_cand.base.base_address and
                   p1.local_cand.base.base_port == p2.local_cand.base.base_port and
                   p1.local_cand.base.address == p2.local_cand.base.address and
                   p1.local_cand.base.port == p2.local_cand.base.port and
                   p1.remote_cand.address == p2.remote_cand.address and
                   p1.remote_cand.port == p2.remote_cand.port

  defguardp is_response(class) when class in [:success_response, :error_response]

  @type t() :: struct()

  defstruct [
    :controlling_process,
    :on_connection_state_change,
    :on_gathering_state_change,
    :on_data,
    :on_new_candidate,
    :if_discovery_module,
    :transport_module,
    :gatherer,
    :ta_timer,
    :role,
    :tiebreaker,
    :selected_pair,
    :local_ufrag,
    :local_pwd,
    :remote_ufrag,
    :remote_pwd,
    state: :new,
    gathering_transactions: %{},
    checklist: %{},
    conn_checks: %{},
    gathering_state: :new,
    eoc: false,
    # {did we nominate pair, pair id}
    nominating?: {false, nil},
    local_cands: %{},
    remote_cands: [],
    stun_servers: [],
    turn_servers: [],
    # stats
    bytes_sent: 0,
    bytes_received: 0,
    packets_sent: 0,
    packets_received: 0
  ]

  @spec new(Keyword.t()) :: t()
  def new(opts) do
    stun_servers = parse_stun_servers(opts[:stun_servers] || [])

    {local_ufrag, local_pwd} = generate_credentials()

    controlling_process = Keyword.fetch!(opts, :controlling_process)

    if_discovery_module = opts[:if_discovery_module] || IfDiscovery.Inet
    transport_module = opts[:transport_module] || Transport.UDP
    ip_filter = opts[:ip_filter] || fn _ -> true end

    %__MODULE__{
      controlling_process: controlling_process,
      on_connection_state_change: opts[:on_connection_state_change] || controlling_process,
      on_gathering_state_change: opts[:on_gathering_state_change] || controlling_process,
      on_data: opts[:on_data] || controlling_process,
      on_new_candidate: opts[:on_new_candidate] || controlling_process,
      if_discovery_module: if_discovery_module,
      transport_module: transport_module,
      gatherer: Gatherer.new(if_discovery_module, transport_module, ip_filter),
      role: Keyword.fetch!(opts, :role),
      tiebreaker: generate_tiebreaker(),
      local_ufrag: local_ufrag,
      local_pwd: local_pwd,
      stun_servers: stun_servers
    }
  end

  @spec on_gathering_state_change(t(), pid() | nil) :: t()
  def on_gathering_state_change(ice_agent, send_to) do
    %__MODULE__{ice_agent | on_gathering_state_change: send_to}
  end

  @spec on_connection_state_change(t(), pid() | nil) :: t()
  def on_connection_state_change(ice_agent, send_to) do
    %__MODULE__{ice_agent | on_connection_state_change: send_to}
  end

  @spec on_data(t(), pid() | nil) :: t()
  def on_data(ice_agent, send_to) do
    %__MODULE__{ice_agent | on_data: send_to}
  end

  @spec on_new_candidate(t(), pid() | nil) :: t()
  def on_new_candidate(ice_agent, send_to) do
    %__MODULE__{ice_agent | on_new_candidate: send_to}
  end

  @spec get_local_credentials(t()) :: {binary(), binary()}
  def get_local_credentials(ice_agent) do
    {ice_agent.local_ufrag, ice_agent.local_pwd}
  end

  @spec get_local_candidates(t()) :: [binary()]
  def get_local_candidates(ice_agent) do
    Enum.map(ice_agent.local_cands, fn {_, %cand_mod{} = cand} ->
      cand_mod.marshal(cand)
    end)
  end

  @spec get_remote_candidates(t()) :: [binary()]
  def get_remote_candidates(ice_agent) do
    Enum.map(ice_agent.remote_cands, &ExICE.Candidate.marshal/1)
  end

  @spec get_stats(t()) :: map()
  def get_stats(ice_agent) do
    local_cands =
      ice_agent.local_cands
      |> Map.values()
      |> Enum.map(fn %cand_mod{} = cand -> cand_mod.to_candidate(cand) end)

    candidate_pairs =
      ice_agent.checklist
      |> Map.values()
      |> Enum.map(&CandidatePair.to_candidate_pair(&1))

    %{
      bytes_sent: ice_agent.bytes_sent,
      bytes_received: ice_agent.bytes_received,
      packets_sent: ice_agent.packets_sent,
      packets_received: ice_agent.packets_received,
      state: ice_agent.state,
      role: ice_agent.role,
      local_ufrag: ice_agent.local_ufrag,
      local_candidates: local_cands,
      remote_candidates: ice_agent.remote_cands,
      candidate_pairs: candidate_pairs
    }
  end

  @spec set_remote_credentials(t(), binary(), binary()) :: t()
  def set_remote_credentials(
        %__MODULE__{remote_ufrag: nil, remote_pwd: nil} = ice_agent,
        ufrag,
        pwd
      ) do
    Logger.debug("Setting remote credentials: #{inspect(ufrag)}:#{inspect(pwd)}")
    %__MODULE__{ice_agent | remote_ufrag: ufrag, remote_pwd: pwd}
  end

  def set_remote_credentials(
        %__MODULE__{remote_ufrag: ufrag, remote_pwd: pwd} = ice_agent,
        ufrag,
        pwd
      ) do
    Logger.warning("Passed the same remote credentials to be set. Ignoring.")
    ice_agent
  end

  def set_remote_credentials(ice_agent, ufrag, pwd) do
    Logger.debug("New remote credentials different than the current ones. Restarting ICE")
    ice_agent = do_restart(ice_agent)
    %__MODULE__{ice_agent | remote_ufrag: ufrag, remote_pwd: pwd}
  end

  @spec gather_candidates(t()) :: t()
  def gather_candidates(%__MODULE__{gathering_state: :gathering} = ice_agent) do
    Logger.warning("Can't gather candidates. Gathering already in progress. Ignoring.")
    ice_agent
  end

  def gather_candidates(%__MODULE__{gathering_state: :complete} = ice_agent) do
    Logger.warning("Can't gather candidates. ICE restart needed. Ignoring.")
    ice_agent
  end

  def gather_candidates(%__MODULE__{gathering_state: :new} = ice_agent) do
    Logger.debug("Gathering state change: #{ice_agent.gathering_state} -> gathering")
    notify(ice_agent.on_gathering_state_change, {:gathering_state_change, :gathering})
    ice_agent = %{ice_agent | gathering_state: :gathering}

    {:ok, host_candidates} = Gatherer.gather_host_candidates(ice_agent.gatherer)

    for %cand_mod{} = cand <- host_candidates do
      notify(ice_agent.on_new_candidate, {:new_candidate, cand_mod.marshal(cand)})
    end

    gathering_transactions =
      for stun_server <- ice_agent.stun_servers, host_cand <- host_candidates, into: %{} do
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

    local_cands = Map.new(host_candidates, fn cand -> {cand.base.id, cand} end)

    %{ice_agent | gathering_transactions: gathering_transactions, local_cands: local_cands}
    |> update_gathering_state()
    |> update_ta_timer()
  end

  @spec add_remote_candidate(t(), String.t()) :: t()
  def add_remote_candidate(%__MODULE__{eoc: true} = ice_agent, remote_cand) do
    Logger.warning(
      "Received remote candidate after end-of-candidates. Ignoring. Candidate: #{inspect(remote_cand)}"
    )

    ice_agent
  end

  def add_remote_candidate(ice_agent, remote_cand) do
    Logger.debug("New remote candidate: #{inspect(remote_cand)}")

    resolve_address = fn
      remote_cand when is_binary(remote_cand.address) ->
        Logger.debug("Trying to resolve addr: #{remote_cand.address}")

        case ExICE.Priv.MDNS.Resolver.gethostbyname(remote_cand.address) do
          {:ok, addr} ->
            Logger.debug("Successfully resolved #{remote_cand.address} to #{inspect(addr)}")
            remote_cand = %ExICE.Candidate{remote_cand | address: addr}
            {:ok, remote_cand}

          {:error, reason} = err ->
            Logger.debug("Couldn't resolve #{remote_cand.address}, reason: #{reason}")
            err
        end

      remote_cand ->
        {:ok, remote_cand}
    end

    with {_, {:ok, remote_cand}} <- {:unmarshal, ExICE.Candidate.unmarshal(remote_cand)},
         {_, {:ok, remote_cand}} <- {:resolve_address, resolve_address.(remote_cand)} do
      ice_agent = do_add_remote_candidate(ice_agent, remote_cand)
      Logger.debug("Successfully added remote candidate.")

      ice_agent
      |> update_connection_state()
      |> update_ta_timer()
    else
      {operation, {:error, reason}} ->
        Logger.warning("""
        Invalid remote candidate. Couldn't #{operation}, reason: #{inspect(reason)}. Ignoring.
        """)

        ice_agent
    end
  end

  @spec end_of_candidates(t()) :: t()
  def end_of_candidates(%__MODULE__{role: :controlled} = ice_agent) do
    ice_agent = %{ice_agent | eoc: true}
    # we might need to move to the completed state
    update_connection_state(ice_agent)
  end

  def end_of_candidates(%__MODULE__{role: :controlling} = ice_agent) do
    ice_agent = %{ice_agent | eoc: true}
    # check wheter it's time to nominate and if yes, try noimnate
    maybe_nominate(ice_agent)
  end

  @spec send_data(t(), binary()) :: t()
  def send_data(%__MODULE__{state: state} = ice_agent, data)
      when state in [:connected, :completed] do
    %CandidatePair{} =
      pair = ice_agent.selected_pair || Checklist.get_valid_pair(ice_agent.checklist)

    dst = {pair.remote_cand.address, pair.remote_cand.port}

    case do_send(ice_agent, pair.local_cand, dst, data) do
      {:ok, ice_agent} ->
        %{
          ice_agent
          | bytes_sent: ice_agent.bytes_sent + byte_size(data),
            packets_sent: ice_agent.packets_sent + 1
        }

      {:error, ice_agent} ->
        ice_agent
    end
  end

  def send_data(%__MODULE__{state: state} = ice_agent, _data) do
    Logger.warning("""
    Cannot send data in ICE state: #{inspect(state)}. \
    Data can only be sent in state :connected or :completed. Ignoring.\
    """)

    ice_agent
  end

  @spec restart(t()) :: t()
  def restart(ice_agent) do
    Logger.debug("Restarting ICE")
    do_restart(ice_agent)
  end

  @spec handle_timeout(t()) :: t()
  def handle_timeout(%__MODULE__{remote_ufrag: nil, remote_pwd: nil} = ice_agent) do
    # TODO we can do this better i.e.
    # allow for executing gathering transactions
    Logger.debug("Ta timer fired but there are no remote credentials. Scheduling next check")
    ta_timer = Process.send_after(self(), :ta_timeout, @ta_timeout)
    ice_agent = %{ice_agent | ta_timer: ta_timer}
    update_ta_timer(ice_agent)
  end

  def handle_timeout(%__MODULE__{state: state} = ice_agent)
      when state.state in [:completed, :failed] do
    Logger.warning("""
    Ta timer fired in unexpected state: #{state}.
    Trying to update gathering and connection states.
    """)

    ice_agent
    |> update_gathering_state()
    |> update_connection_state()
    |> update_ta_timer()
  end

  def handle_timeout(ice_agent) do
    ice_agent =
      ice_agent
      |> timeout_pending_transactions()
      |> update_gathering_state()
      |> update_connection_state()
      |> maybe_nominate()

    if ice_agent.state in [:completed, :failed] do
      update_ta_timer(ice_agent)
    else
      {transaction_executed, ice_agent} =
        case Checklist.get_next_pair(ice_agent.checklist) do
          %CandidatePair{} = pair ->
            Logger.debug("Sending conn check on pair: #{inspect(pair.id)}")
            ice_agent = send_conn_check(ice_agent, pair)
            {true, ice_agent}

          nil ->
            # credo:disable-for-lines:3 Credo.Check.Refactor.Nesting
            case get_next_gathering_transaction(ice_agent.gathering_transactions) do
              {_t_id, transaction} ->
                case handle_gathering_transaction(ice_agent, transaction) do
                  {:ok, ice_agent} -> {true, ice_agent}
                  {:error, ice_agent} -> {false, ice_agent}
                end

              nil ->
                {false, ice_agent}
            end
        end

      unless transaction_executed do
        Logger.debug("Couldn't find transaction to execute. Did Ta timer fired without the need?")
      end

      # schedule next check and call update_ta_timer
      # if the next check is not needed, update_ta_timer will
      # cancel it
      ta_timer = Process.send_after(self(), :ta_timeout, @ta_timeout)
      ice_agent = %{ice_agent | ta_timer: ta_timer}
      update_ta_timer(ice_agent)
    end
  end

  @spec handle_keepalive(t(), integer()) :: t()
  def handle_keepalive(%__MODULE__{selected_pair: s_pair} = ice_agent, id)
      when not is_nil(s_pair) and s_pair.id == id do
    # if pair was selected, send keepalives only on that pair
    pair = CandidatePair.schedule_keepalive(s_pair)
    ice_agent = %__MODULE__{ice_agent | checklist: Map.put(ice_agent.checklist, id, pair)}
    send_keepalive(ice_agent, ice_agent.checklist[id])
  end

  def handle_keepalive(%__MODULE__{selected_pair: s_pair} = ice_agent, _id)
      when not is_nil(s_pair) do
    # note: current implementation assumes that, if selected pair exists, none of the already existing
    # valid pairs will ever become selected (only new appearing valid pairs)
    # that's why there's no call to `CandidatePair.schedule_keepalive/1`
    ice_agent
  end

  def handle_keepalive(ice_agent, id) do
    # TODO: keepalives should be send only if no data has been send for @tr_timeout
    # atm, we send keepalives anyways, also it might be better to pace them with ta_timer
    # TODO: candidates not in a valid pair also should be kept alive (RFC 8445, sect 5.1.1.4)
    case Map.fetch(ice_agent.checklist, id) do
      {:ok, pair} ->
        pair = CandidatePair.schedule_keepalive(pair)
        ice_agent = %__MODULE__{ice_agent | checklist: Map.put(ice_agent.checklist, id, pair)}
        send_keepalive(ice_agent, pair)

      :error ->
        Logger.warning("Received keepalive request for non-existant candidate pair")
        ice_agent
    end
  end

  @spec handle_udp(
          t(),
          ExICE.Priv.Transport.socket(),
          :inet.ip_address(),
          :inet.port_number(),
          binary()
        ) :: t()
  def handle_udp(ice_agent, socket, src_ip, src_port, packet) do
    local_cands = Map.values(ice_agent.local_cands)

    case find_host_cand(local_cands, socket) do
      nil ->
        Logger.debug(
          "No local candidate corresponding to message received from #{inspect(src_ip)}:#{src_port}. Ignoring."
        )

        ice_agent

      %cand_mod{} = local_cand ->
        case cand_mod.receive_data(local_cand, src_ip, src_port, packet) do
          {:ok, local_cand} ->
            %{
              ice_agent
              | local_cands: Map.put(ice_agent.local_cands, local_cand.base.id, local_cand)
            }

          {:ok, packet, local_cand} ->
            local_cands = Map.put(ice_agent.local_cands, local_cand.base.id, local_cand)
            ice_agent = %{ice_agent | local_cands: local_cands}

            do_handle_udp(ice_agent, local_cand, src_ip, src_port, packet)

          {:error, reason, local_cand} ->
            Logger.warning("""
            Error receiving data on candidate, reason: #{reason}.
            Candidate: #{inspect(local_cand)}.
            Closing candidate.
            """)

            close_candidate(ice_agent, local_cand)
        end
    end
  end

  defp do_handle_udp(ice_agent, local_cand, src_ip, src_port, packet) do
    if ExSTUN.stun?(packet) do
      case ExSTUN.Message.decode(packet) do
        {:ok, msg} ->
          handle_stun_msg(ice_agent, local_cand, src_ip, src_port, msg)

        {:error, reason} ->
          Logger.warning("Couldn't decode stun message: #{inspect(reason)}")
          ice_agent
      end
    else
      notify(ice_agent.on_data, {:data, packet})

      %{
        ice_agent
        | bytes_received: ice_agent.bytes_received + byte_size(packet),
          packets_received: ice_agent.packets_received + 1
      }
    end
  end

  defp close_candidate(ice_agent, local_cand) do
    local_cands = Map.delete(ice_agent.local_cands, local_cand.base.id)

    selected_pair =
      if ice_agent.selected_pair != nil and
           ice_agent.selected_pair.local_cand.base.id == local_cand.base.id,
         do: nil,
         else: ice_agent.selected_pair

    nominating? =
      case ice_agent.nominating? do
        {true, pair_id} ->
          pair = Map.fetch!(ice_agent.checklist, pair_id)

          if pair.local_cand.base.id == local_cand.base.id do
            {false, nil}
          else
            ice_agent.nominating?
          end

        other ->
          other
      end

    %{
      ice_agent
      | local_cands: local_cands,
        selected_pair: selected_pair,
        checklist: Checklist.prune(ice_agent.checklist, local_cand),
        nominating?: nominating?
    }
    |> update_connection_state()
  end

  defp do_add_remote_candidate(ice_agent, remote_cand) do
    local_cands = get_matching_candidates_remote(Map.values(ice_agent.local_cands), remote_cand)

    checklist_foundations = Checklist.get_foundations(ice_agent.checklist)

    new_pairs =
      for local_cand <- local_cands, into: %{} do
        local_cand =
          if local_cand.base.type == :srflx do
            local_cand = put_in(local_cand.base.address, local_cand.base.base_address)
            put_in(local_cand.base.port, local_cand.base.base_port)
          else
            local_cand
          end

        pair_state = get_pair_state(local_cand, remote_cand, checklist_foundations)
        pair = CandidatePair.new(local_cand, remote_cand, ice_agent.role, pair_state)
        {pair.id, pair}
      end

    checklist = Checklist.prune(Map.merge(ice_agent.checklist, new_pairs))

    added_pairs = Map.drop(checklist, Map.keys(ice_agent.checklist))

    if added_pairs == %{} do
      Logger.debug("Not adding any new pairs as they were redundant")
    else
      Logger.debug("New candidate pairs: #{inspect(added_pairs)}")
    end

    %__MODULE__{
      ice_agent
      | checklist: checklist,
        remote_cands: [remote_cand | ice_agent.remote_cands]
    }
  end

  defp get_next_gathering_transaction(gathering_transactions) do
    Enum.find(gathering_transactions, fn {_t_id, t} -> t.state == :waiting end)
  end

  defp handle_gathering_transaction(
         ice_agent,
         %{t_id: t_id, host_cand: host_cand, stun_server: stun_server} = t
       ) do
    Logger.debug("""
    Sending binding request to gather srflx candidate for:
    host_cand: #{inspect(host_cand)},
    stun_server: #{inspect(stun_server)}
    """)

    case Gatherer.gather_srflx_candidate(ice_agent.gatherer, t_id, host_cand, stun_server) do
      :ok ->
        now = System.monotonic_time(:millisecond)
        t = %{t | state: :in_progress, send_time: now}
        gathering_transactions = Map.put(ice_agent.gathering_transactions, t_id, t)
        ice_agent = %__MODULE__{ice_agent | gathering_transactions: gathering_transactions}
        {:ok, ice_agent}

      {:error, reason} ->
        Logger.debug("Couldn't send binding request, reason: #{reason}")

        gathering_transactions =
          put_in(ice_agent.gathering_transactions, [t.t_id, :state], :failed)

        ice_agent = %__MODULE__{ice_agent | gathering_transactions: gathering_transactions}
        ice_agent = update_gathering_state(ice_agent)

        {:error, ice_agent}
    end
  end

  defp timeout_pending_transactions(ice_agent) do
    now = System.monotonic_time(:millisecond)
    ice_agent = timeout_gathering_transactions(ice_agent, now)
    timeout_conn_checks(ice_agent, now)
  end

  defp timeout_conn_checks(ice_agent, now) do
    {stale_cc, cc} =
      Enum.split_with(ice_agent.conn_checks, fn {_id, %{send_time: send_time}} ->
        now - send_time >= @hto
      end)

    {stale_cc, cc} = {Map.new(stale_cc), Map.new(cc)}

    checklist =
      if stale_cc != %{} do
        Logger.debug("Connectivity checks timed out: #{inspect(Map.keys(stale_cc))}")
        stale_pair_ids = Enum.map(stale_cc, fn {_id, %{pair_id: pair_id}} -> pair_id end)
        Logger.debug("Pairs failed. Reason: timeout. Pairs: #{inspect(stale_pair_ids)}")
        Checklist.timeout_pairs(ice_agent.checklist, stale_pair_ids)
      else
        ice_agent.checklist
      end

    %__MODULE__{ice_agent | checklist: checklist, conn_checks: cc}
  end

  defp timeout_gathering_transactions(ice_agent, now) do
    {stale_gath_trans, gath_trans} =
      Enum.split_with(ice_agent.gathering_transactions, fn {_id,
                                                            %{
                                                              state: t_state,
                                                              send_time: send_time
                                                            }} ->
        t_state == :in_progress and now - send_time >= @hto
      end)

    gath_trans = Map.new(gath_trans)

    if stale_gath_trans != [] do
      ids = Enum.map(stale_gath_trans, fn {id, _} -> id end)
      Logger.debug("Gathering transactions timed out: #{inspect(ids)}")
    end

    %__MODULE__{ice_agent | gathering_transactions: gath_trans}
  end

  defp handle_stun_msg(ice_agent, local_cand, src_ip, src_port, %Message{} = msg) do
    # TODO revisit 7.3.1.4

    case msg.type do
      %Type{class: :request, method: :binding} ->
        Logger.debug("""
        Received binding request from: #{inspect({src_ip, src_port})}, on: #{inspect(local_cand.base.base_address)} \
        """)

        handle_binding_request(ice_agent, local_cand, src_ip, src_port, msg)

      %Type{class: class, method: :binding}
      when is_response(class) and is_map_key(ice_agent.conn_checks, msg.transaction_id) ->
        Logger.debug("""
        Received conn check response from: #{inspect({src_ip, src_port})}, on: #{inspect(local_cand.base.base_address)} \
        """)

        handle_conn_check_response(ice_agent, local_cand, src_ip, src_port, msg)

      %Type{class: class, method: :binding}
      when is_response(class) and is_map_key(ice_agent.gathering_transactions, msg.transaction_id) ->
        Logger.debug("""
        Received gathering transaction response from: #{inspect({src_ip, src_port})}, on: #{inspect(local_cand.base.base_address)} \
        """)

        handle_gathering_transaction_response(ice_agent, msg)

      %Type{class: class, method: :binding} when is_response(class) ->
        Logger.warning("""
        Ignoring binding response with unknown t_id: #{msg.transaction_id}.
        Is it retransmission or we called ICE restart?
        """)

        ice_agent

      other ->
        Logger.warning("""
        Unknown msg from: #{inspect({src_ip, src_port})}, on: #{inspect(local_cand.base.base_address)}, msg: #{inspect(other)} \
        """)

        ice_agent
    end
    |> update_gathering_state()
    |> update_connection_state()
    |> maybe_nominate()
    |> update_ta_timer()
  end

  ## BINDING REQUEST HANDLING ##
  defp handle_binding_request(ice_agent, local_cand, src_ip, src_port, msg) do
    with :ok <- check_username(msg, ice_agent.local_ufrag),
         :ok <- authenticate_msg(msg, ice_agent.local_pwd),
         {:ok, prio_attr} <- get_prio_attribute(msg),
         {:ok, role_attr} <- get_role_attribute(msg),
         {:ok, use_cand_attr} <- get_use_cand_attribute(msg),
         {:ok, ice_agent} <- check_req_role_conflict(ice_agent, role_attr) do
      {remote_cand, ice_agent} =
        get_or_create_remote_cand(ice_agent, src_ip, src_port, prio_attr)

      pair = CandidatePair.new(local_cand, remote_cand, ice_agent.role, :waiting)

      @conn_check_handler[ice_agent.role].handle_conn_check_request(
        ice_agent,
        pair,
        msg,
        use_cand_attr
      )
    else
      {:error, reason}
      when reason in [
             :invalid_username,
             :no_username,
             :invalid_message_integrity,
             :no_message_integrity,
             :invalid_priority,
             :no_priority,
             :invalid_role,
             :no_role,
             :invalid_use_candidate
           ] ->
        Logger.debug("""
        Invalid binding request, reason: #{reason}. \
        Sending bad request error response\
        """)

        send_bad_request_error_response(ice_agent, local_cand, {src_ip, src_port}, msg)

      {:error, reason} when reason in [:no_matching_username, :no_matching_message_integrity] ->
        Logger.debug("""
        Invalid binding request, reason: #{reason}. \
        Sending unauthenticated error response\
        """)

        send_unauthenticated_error_response(ice_agent, local_cand, {src_ip, src_port}, msg)

      {:error, :role_conflict, tiebreaker} ->
        Logger.debug("""
        Role conflict. We retain our role which is: #{ice_agent.role}. Sending error response.
        Our tiebreaker: #{ice_agent.tiebreaker}
        Peer's tiebreaker: #{tiebreaker}\
        """)

        send_role_conflict_error_response(ice_agent, local_cand, {src_ip, src_port}, msg)

      {:error, reason} ->
        Logger.debug("Ignoring binding request, reason: #{reason}")
        ice_agent
    end
  end

  defp get_prio_attribute(msg) do
    case Message.get_attribute(msg, Priority) do
      {:ok, _} = attr -> attr
      {:error, :invalid_priority} = err -> err
      nil -> {:error, :no_priority}
    end
  end

  defp get_role_attribute(msg) do
    role_attr =
      Message.get_attribute(msg, ICEControlling) || Message.get_attribute(msg, ICEControlled)

    case role_attr do
      {:ok, _} ->
        role_attr

      {:error, reason} when reason in [:invalid_ice_controlling, :invalid_ice_controlled] ->
        {:error, :invalid_role}

      nil ->
        {:error, :no_role}
    end
  end

  defp get_use_cand_attribute(msg) do
    # this function breaks the convention...
    case Message.get_attribute(msg, UseCandidate) do
      {:ok, attr} -> {:ok, attr}
      {:error, :invalid_use_candidate} = err -> err
      nil -> {:ok, nil}
    end
  end

  defp check_req_role_conflict(
         %__MODULE__{role: :controlling} = ice_agent,
         %ICEControlling{tiebreaker: tiebreaker}
       )
       when ice_agent.tiebreaker >= tiebreaker do
    {:error, :role_conflict, tiebreaker}
  end

  defp check_req_role_conflict(
         %__MODULE__{role: :controlling} = ice_agent,
         %ICEControlling{tiebreaker: tiebreaker}
       ) do
    Logger.debug("""
    Role conflict, switching our role to controlled. Recomputing pairs priority.
    Our tiebreaker: #{ice_agent.tiebreaker}
    Peer's tiebreaker: #{tiebreaker}\
    """)

    checklist = Checklist.recompute_pair_prios(ice_agent.checklist, :controlled)
    {:ok, %__MODULE__{ice_agent | role: :controlled, checklist: checklist}}
  end

  defp check_req_role_conflict(
         %__MODULE__{role: :controlled} = ice_agent,
         %ICEControlled{tiebreaker: tiebreaker}
       )
       when ice_agent.tiebreaker >= tiebreaker do
    Logger.debug("""
    Role conflict, switching our role to controlling. Recomputing pairs priority.
    Our tiebreaker: #{ice_agent.tiebreaker}
    Peer's tiebreaker: #{tiebreaker}\
    """)

    checklist = Checklist.recompute_pair_prios(ice_agent.checklist, :controlling)
    {:ok, %__MODULE__{ice_agent | role: :controlling, checklist: checklist}}
  end

  defp check_req_role_conflict(%__MODULE__{role: :controlled}, %ICEControlled{
         tiebreaker: tiebreaker
       }) do
    {:error, :role_conflict, tiebreaker}
  end

  defp check_req_role_conflict(ice_agent, _role_attr), do: {:ok, ice_agent}

  defp check_username(msg, local_ufrag) do
    # See RFC 8445, sec. 7.3.
    case Message.get_attribute(msg, Username) do
      {:ok, %Username{value: username}} ->
        if String.starts_with?(username, local_ufrag <> ":"),
          do: :ok,
          else: {:error, :no_matching_username}

      {:error, :invalid_username} = err ->
        err

      nil ->
        {:error, :no_username}
    end
  end

  ## BINDING RESPONSE HANDLING ##

  defp handle_conn_check_response(ice_agent, local_cand, src_ip, src_port, msg) do
    {%{pair_id: pair_id}, conn_checks} = Map.pop!(ice_agent.conn_checks, msg.transaction_id)
    ice_agent = %__MODULE__{ice_agent | conn_checks: conn_checks}
    conn_check_pair = Map.fetch!(ice_agent.checklist, pair_id)

    # check that the source and destination transport
    # addresses are symmetric - see sec. 7.2.5.2.1
    if symmetric?(local_cand.base.socket, {src_ip, src_port}, conn_check_pair) do
      case msg.type.class do
        :success_response -> handle_conn_check_success_response(ice_agent, conn_check_pair, msg)
        :error_response -> handle_conn_check_error_response(ice_agent, conn_check_pair, msg)
      end
    else
      Logger.warning("""
      Ignoring conn check response, non-symmetric src and dst addresses.
      Sent from: #{inspect({conn_check_pair.local_cand.base.base_address, conn_check_pair.local_cand.base.base_port})}, \
      to: #{inspect({conn_check_pair.remote_cand.address, conn_check_pair.remote_cand.port})}
      Recv from: #{inspect({src_ip, src_port})}, on: #{inspect({local_cand.base.base_address, local_cand.base.base_port})}
      Pair failed: #{conn_check_pair.id}
      """)

      conn_check_pair = %CandidatePair{conn_check_pair | state: :failed}

      checklist = Map.put(ice_agent.checklist, conn_check_pair.id, conn_check_pair)
      %__MODULE__{ice_agent | checklist: checklist}
    end
  end

  defp handle_conn_check_success_response(ice_agent, conn_check_pair, msg) do
    with :ok <- authenticate_msg(msg, ice_agent.remote_pwd),
         {:ok, xor_addr} <- Message.get_attribute(msg, XORMappedAddress) do
      {local_cand, ice_agent} = get_or_create_local_cand(ice_agent, xor_addr, conn_check_pair)
      remote_cand = conn_check_pair.remote_cand

      valid_pair =
        CandidatePair.new(local_cand, remote_cand, ice_agent.role, :succeeded, valid?: true)

      checklist_pair = Checklist.find_pair(ice_agent.checklist, valid_pair)

      {pair_id, ice_agent} =
        add_valid_pair(ice_agent, valid_pair, conn_check_pair, checklist_pair)

      pair = CandidatePair.schedule_keepalive(ice_agent.checklist[pair_id])
      checklist = Map.put(ice_agent.checklist, pair_id, pair)
      ice_agent = %__MODULE__{ice_agent | checklist: checklist}

      # get new conn check pair as it will have updated
      # discovered and succeeded pair fields
      conn_check_pair = Map.fetch!(ice_agent.checklist, conn_check_pair.id)
      nominate? = conn_check_pair.nominate?
      conn_check_pair = %CandidatePair{conn_check_pair | nominate?: false}
      checklist = Map.put(ice_agent.checklist, conn_check_pair.id, conn_check_pair)
      ice_agent = %__MODULE__{ice_agent | checklist: checklist}
      @conn_check_handler[ice_agent.role].update_nominated_flag(ice_agent, pair_id, nominate?)
    else
      {:error, reason} ->
        Logger.debug("""
        Ignoring conn check response, reason: #{reason}.
        Conn check tid: #{inspect(msg.transaction_id)},
        Conn check pair: #{inspect(conn_check_pair.id)}.
        """)

        ice_agent
    end
  end

  defp handle_conn_check_error_response(ice_agent, conn_check_pair, msg) do
    # We only authenticate role conflict as it changes our state.
    # We don't add message-integrity to bad request and unauthenticated errors
    # so we also don't expect to receive it.
    # In the worst case scenario, we won't allow for the connection.
    case Message.get_attribute(msg, ErrorCode) do
      {:ok, %ErrorCode{code: 487}} ->
        handle_role_confilct_error_response(ice_agent, conn_check_pair, msg)

      other ->
        Logger.debug(
          "Conn check failed due to error resposne from the peer, error: #{inspect(other)}"
        )

        conn_check_pair = %CandidatePair{conn_check_pair | state: :failed}
        checklist = Map.put(ice_agent.checklist, conn_check_pair.id, conn_check_pair)
        %__MODULE__{ice_agent | checklist: checklist}
    end
  end

  defp handle_role_confilct_error_response(ice_agent, conn_check_pair, msg) do
    case authenticate_msg(msg, ice_agent.remote_pwd) do
      :ok ->
        new_role = if ice_agent.role == :controlling, do: :controlled, else: :controlling

        Logger.debug("""
        Conn check failed due to role conflict. Changing our role to: #{new_role}, \
        recomputing pair priorities, regenerating tiebreaker and rescheduling conn check \
        """)

        conn_check_pair = %CandidatePair{conn_check_pair | state: :waiting}
        checklist = Map.replace!(ice_agent.checklist, conn_check_pair.id, conn_check_pair)
        tiebreaker = generate_tiebreaker()
        %__MODULE__{ice_agent | role: new_role, checklist: checklist, tiebreaker: tiebreaker}

      {:error, reason} ->
        Logger.debug(
          "Couldn't authenticate conn check error response, reason: #{reason}. Ignoring."
        )

        ice_agent
    end
  end

  defp handle_gathering_transaction_response(ice_agent, msg) do
    case msg.type.class do
      :success_response ->
        handle_gathering_transaction_success_response(ice_agent, msg)

      :error_response ->
        handle_gathering_transaction_error_response(ice_agent, msg)
    end
  end

  defp handle_gathering_transaction_success_response(ice_agent, msg) do
    t = Map.fetch!(ice_agent.gathering_transactions, msg.transaction_id)

    {:ok, %XORMappedAddress{address: xor_addr, port: xor_port}} =
      Message.get_attribute(msg, XORMappedAddress)

    ice_agent =
      case find_local_cand(Map.values(ice_agent.local_cands), xor_addr, xor_port) do
        nil ->
          c =
            Candidate.Srflx.new(
              address: xor_addr,
              port: xor_port,
              base_address: t.host_cand.base.address,
              base_port: t.host_cand.base.port,
              transport_module: ice_agent.transport_module,
              socket: t.host_cand.base.socket
            )

          Logger.debug("New srflx candidate: #{inspect(c)}")
          notify(ice_agent.on_new_candidate, {:new_candidate, Candidate.Srflx.marshal(c)})
          add_srflx_cand(ice_agent, c)

        cand ->
          Logger.debug("""
          Not adding srflx candidate as we already have a candidate with the same address.
          Candidate: #{inspect(cand)}
          """)

          ice_agent
      end

    gathering_transactions =
      Map.update!(ice_agent.gathering_transactions, t.t_id, fn t -> %{t | state: :complete} end)

    %__MODULE__{ice_agent | gathering_transactions: gathering_transactions}
  end

  defp handle_gathering_transaction_error_response(ice_agent, msg) do
    t = Map.fetch!(ice_agent.gathering_transactions, msg.transaction_id)

    error_code =
      case Message.get_attribute(msg, ErrorCode) do
        {:ok, error_code} -> error_code
        _other -> nil
      end

    Logger.debug(
      "Gathering transaction failed, t_id: #{msg.transaction_id}, reason: #{inspect(error_code)}"
    )

    gathering_transactions =
      Map.update!(ice_agent.gathering_transactions, t.t_id, fn t -> %{t | state: :failed} end)

    %__MODULE__{ice_agent | gathering_transactions: gathering_transactions}
  end

  defp add_srflx_cand(ice_agent, c) do
    # replace address and port with candidate base
    # and prune the checklist - see sec. 6.1.2.4
    local_cand = %{c | base: %{c.base | address: c.base.base_address, port: c.base.base_port}}

    remote_cands = get_matching_candidates_local(ice_agent.remote_cands, local_cand)

    checklist_foundations = Checklist.get_foundations(ice_agent.checklist)

    new_pairs =
      for remote_cand <- remote_cands, into: %{} do
        pair_state = get_pair_state(local_cand, remote_cand, checklist_foundations)
        pair = CandidatePair.new(local_cand, remote_cand, ice_agent.role, pair_state)
        {pair.id, pair}
      end

    checklist = Checklist.prune(Map.merge(ice_agent.checklist, new_pairs))

    added_pairs = Map.drop(checklist, Map.keys(ice_agent.checklist))

    if added_pairs == %{} do
      Logger.debug("Not adding any new pairs as they were redundant")
    else
      Logger.debug("New candidate pairs: #{inspect(added_pairs)}")
    end

    %__MODULE__{
      ice_agent
      | checklist: checklist,
        local_cands: Map.put(ice_agent.local_cands, c.base.id, c)
    }
  end

  # Adds valid pair according to sec 7.2.5.3.2
  # TODO sec. 7.2.5.3.3
  # The agent MUST set the states for all other Frozen candidate pairs in
  # all checklists with the same foundation to Waiting.
  #
  # Check against valid_pair == conn_check_pair before
  # checking against valid_pair == checklist_pair as
  # the second condition is always true if the first one is
  defp add_valid_pair(ice_agent, valid_pair, conn_check_pair, _)
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

    checklist = Map.replace!(ice_agent.checklist, conn_check_pair.id, conn_check_pair)

    ice_agent = %__MODULE__{ice_agent | checklist: checklist}
    {conn_check_pair.id, ice_agent}
  end

  defp add_valid_pair(
         ice_agent,
         valid_pair,
         conn_check_pair,
         %CandidatePair{valid?: true} = checklist_pair
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
      ice_agent.checklist
      |> Map.replace!(checklist_pair.id, checklist_pair)
      |> Map.replace!(conn_check_pair.id, conn_check_pair)

    ice_agent = %__MODULE__{ice_agent | checklist: checklist}
    {checklist_pair.id, ice_agent}
  end

  defp add_valid_pair(ice_agent, valid_pair, conn_check_pair, checklist_pair)
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
      ice_agent.checklist
      |> Map.replace!(conn_check_pair.id, conn_check_pair)
      |> Map.replace!(checklist_pair.id, checklist_pair)

    ice_agent = %__MODULE__{ice_agent | checklist: checklist}
    {checklist_pair.id, ice_agent}
  end

  defp add_valid_pair(ice_agent, valid_pair, conn_check_pair, _) do
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
      ice_agent.checklist
      |> Map.replace!(conn_check_pair.id, conn_check_pair)
      |> Map.put(valid_pair.id, valid_pair)

    ice_agent = %__MODULE__{ice_agent | checklist: checklist}
    {valid_pair.id, ice_agent}
  end

  @doc false
  @spec send_binding_success_response(t(), CandidatePair.t(), Message.t()) :: t()
  def send_binding_success_response(ice_agent, pair, req) do
    src_ip = pair.remote_cand.address
    src_port = pair.remote_cand.port

    type = %Type{class: :success_response, method: :binding}

    resp =
      Message.new(req.transaction_id, type, [%XORMappedAddress{address: src_ip, port: src_port}])
      |> Message.with_integrity(ice_agent.local_pwd)
      |> Message.with_fingerprint()
      |> Message.encode()

    {_result, ice_agent} = do_send(ice_agent, pair.local_cand, {src_ip, src_port}, resp)
    ice_agent
  end

  @doc false
  @spec send_bad_request_error_response(
          t(),
          Candidate.t(),
          {:inet.ip_address(), :inet.port_number()},
          Message.t()
        ) :: t()
  def send_bad_request_error_response(ice_agent, local_cand, dst, req) do
    type = %Type{class: :error_response, method: :binding}

    response =
      Message.new(req.transaction_id, type, [%ErrorCode{code: 400}])
      |> Message.with_fingerprint()
      |> Message.encode()

    {_result, ice_agent} = do_send(ice_agent, local_cand, dst, response)
    ice_agent
  end

  defp send_unauthenticated_error_response(ice_agent, local_cand, dst, req) do
    type = %Type{class: :error_response, method: :binding}

    response =
      Message.new(req.transaction_id, type, [%ErrorCode{code: 401}])
      |> Message.with_fingerprint()
      |> Message.encode()

    {_result, ice_agent} = do_send(ice_agent, local_cand, dst, response)
    ice_agent
  end

  defp send_role_conflict_error_response(ice_agent, local_cand, dst, req) do
    type = %Type{class: :error_response, method: :binding}

    response =
      Message.new(req.transaction_id, type, [%ErrorCode{code: 487}])
      |> Message.with_integrity(ice_agent.local_pwd)
      |> Message.with_fingerprint()
      |> Message.encode()

    {_result, ice_agent} = do_send(ice_agent, local_cand, dst, response)
    ice_agent
  end

  defp get_matching_candidates_local(candidates, %c_mod{} = cand) do
    Enum.filter(candidates, fn c ->
      ExICE.Candidate.family(c) == c_mod.family(cand)
    end)
  end

  defp get_matching_candidates_remote(candidates, cand) do
    Enum.filter(candidates, fn %c_mod{} = c ->
      c_mod.family(c) == ExICE.Candidate.family(cand)
    end)
  end

  defp symmetric?(socket, response_src, conn_check_pair) do
    request_dst = {conn_check_pair.remote_cand.address, conn_check_pair.remote_cand.port}
    response_src == request_dst and socket == conn_check_pair.local_cand.base.socket
  end

  defp get_pair_state(local_cand, remote_cand, checklist_foundations) do
    f = {local_cand.base.foundation, remote_cand.foundation}
    if f in checklist_foundations, do: :frozen, else: :waiting
  end

  defp get_or_create_local_cand(ice_agent, xor_addr, conn_check_pair) do
    local_cand =
      find_local_cand(Map.values(ice_agent.local_cands), xor_addr.address, xor_addr.port)

    if local_cand do
      {local_cand, ice_agent}
    else
      # prflx candidate sec 7.2.5.3.1
      # TODO calculate correct prio and foundation
      cand =
        Candidate.Prflx.new(
          address: xor_addr.address,
          port: xor_addr.port,
          base_address: conn_check_pair.local_cand.base.base_address,
          base_port: conn_check_pair.local_cand.base.base_port,
          transport_module: ice_agent.transport_module,
          socket: conn_check_pair.local_cand.base.socket
        )

      Logger.debug("Adding new local prflx candidate: #{inspect(cand)}")

      ice_agent = %__MODULE__{
        ice_agent
        | local_cands: Map.put(ice_agent.local_cands, cand.base.id, cand)
      }

      {cand, ice_agent}
    end
  end

  defp get_or_create_remote_cand(ice_agent, src_ip, src_port, _prio_attr) do
    case find_remote_cand(ice_agent.remote_cands, src_ip, src_port) do
      nil ->
        # TODO calculate correct prio using prio_attr
        cand = ExICE.Candidate.new(:prflx, address: src_ip, port: src_port)
        Logger.debug("Adding new remote prflx candidate: #{inspect(cand)}")
        ice_agent = %__MODULE__{ice_agent | remote_cands: [cand | ice_agent.remote_cands]}
        {cand, ice_agent}

      %_cand_mod{} = cand ->
        {cand, ice_agent}
    end
  end

  defp maybe_nominate(ice_agent) do
    if time_to_nominate?(ice_agent) do
      Logger.debug("Time to nominate a pair! Looking for a best valid pair...")
      try_nominate(ice_agent)
    else
      ice_agent
    end
  end

  defp time_to_nominate?(%__MODULE__{state: :completed}), do: false

  defp time_to_nominate?(ice_agent) do
    {nominating?, _} = ice_agent.nominating?
    # if we are not during nomination and we know there won't be further candidates,
    # there are no checks waiting or in-progress,
    # and we are the controlling agent, then we can nominate
    nominating? == false and ice_agent.gathering_state == :complete and
      ice_agent.eoc and
      Checklist.finished?(ice_agent.checklist) and
      ice_agent.role == :controlling
  end

  @doc false
  @spec try_nominate(map()) :: map()
  def try_nominate(ice_agent) do
    case Checklist.get_pair_for_nomination(ice_agent.checklist) do
      %CandidatePair{} = pair ->
        Logger.debug("Trying to nominate pair: #{inspect(pair.id)}")
        pair = %CandidatePair{pair | nominate?: true}
        checklist = Map.put(ice_agent.checklist, pair.id, pair)
        ice_agent = %__MODULE__{ice_agent | checklist: checklist, nominating?: {true, pair.id}}
        pair = Map.fetch!(ice_agent.checklist, pair.succeeded_pair_id)
        pair = %CandidatePair{pair | state: :waiting, nominate?: true}
        send_conn_check(ice_agent, pair)

      nil ->
        # TODO revisit this
        # should we check if state.state == :in_progress?
        Logger.debug("""
        No pairs for nomination. ICE failed. #{inspect(ice_agent.checklist, pretty: true)}
        """)

        change_connection_state(ice_agent, :failed)
    end
  end

  defp update_gathering_state(%{gathering_state: :complete} = ice_agent), do: ice_agent

  defp update_gathering_state(ice_agent) do
    transaction_in_progress? =
      Enum.any?(ice_agent.gathering_transactions, fn {_id, %{state: t_state}} ->
        t_state in [:waiting, :in_progress]
      end)

    cond do
      ice_agent.gathering_state == :new and transaction_in_progress? ->
        Logger.debug("Gathering state change: new -> gathering")
        notify(ice_agent.on_gathering_state_change, {:gathering_state_change, :gathering})
        %__MODULE__{ice_agent | gathering_state: :gathering}

      ice_agent.gathering_state == :gathering and not transaction_in_progress? ->
        Logger.debug("Gathering state change: gathering -> complete")
        notify(ice_agent.on_gathering_state_change, {:gathering_state_change, :complete})
        %__MODULE__{ice_agent | gathering_state: :complete}

      true ->
        ice_agent
    end
  end

  defp do_restart(ice_agent) do
    ice_agent.local_cands
    |> Enum.uniq_by(fn {_id, cand} -> cand.base.socket end)
    |> Enum.each(fn {_id, cand} ->
      Logger.debug("""
      Closing local candidate's socket: #{inspect(cand.base.base_address)}:#{cand.base.base_port}.
      """)

      :ok = ice_agent.transport_module.close(cand.base.socket)
    end)

    {ufrag, pwd} = generate_credentials()

    new_ice_state = :checking

    ice_agent =
      if new_ice_state != ice_agent.state do
        change_connection_state(ice_agent, :checking)
      else
        ice_agent
      end

    Logger.debug("Gathering state change: #{ice_agent.gathering_state} -> new")
    notify(ice_agent.on_gathering_state_change, {:gathering_state_change, :new})

    %__MODULE__{
      ice_agent
      | state: new_ice_state,
        gathering_state: :new,
        gathering_transactions: %{},
        selected_pair: nil,
        conn_checks: %{},
        checklist: %{},
        local_cands: %{},
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

  defp find_local_cand(cands, ip, port) do
    Enum.find(cands, fn cand -> cand.base.address == ip and cand.base.port == port end)
  end

  defp find_remote_cand(cands, ip, port) do
    Enum.find(cands, fn cand -> cand.address == ip and cand.port == port end)
  end

  defp find_host_cand(cands, socket) do
    # this function returns only host candidates
    Enum.find(cands, fn cand -> cand.base.socket == socket and cand.base.type == :host end)
  end

  defp parse_stun_servers(stun_servers) do
    stun_servers
    |> Enum.map(fn stun_server ->
      case ExSTUN.URI.parse(stun_server) do
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
    with :ok <- Message.authenticate(msg, local_pwd),
         :ok <- Message.check_fingerprint(msg) do
      :ok
    else
      {:error, _reason} = err -> err
    end
  end

  @doc false
  @spec change_connection_state(t(), atom()) :: t()
  def change_connection_state(ice_agent, new_conn_state) do
    Logger.debug("Connection state change: #{ice_agent.state} -> #{new_conn_state}")
    notify(ice_agent.on_connection_state_change, {:connection_state_change, new_conn_state})
    %__MODULE__{ice_agent | state: new_conn_state}
  end

  defp update_connection_state(%__MODULE__{state: :new} = ice_agent) do
    if Checklist.waiting?(ice_agent.checklist) or Checklist.in_progress?(ice_agent.checklist) do
      change_connection_state(ice_agent, :checking)
    else
      ice_agent
    end
  end

  defp update_connection_state(%__MODULE__{state: :checking} = ice_agent) do
    cond do
      Checklist.get_valid_pair(ice_agent.checklist) != nil ->
        Logger.debug("Found a valid pair. Changing connection state to connected")
        change_connection_state(ice_agent, :connected)

      ice_agent.eoc == true and ice_agent.gathering_state == :complete and
          Checklist.finished?(ice_agent.checklist) ->
        Logger.debug("""
        Finished all conn checks, there won't be any further local or remote candidates
        and we don't have any valid or selected pair. Changing connection state to failed.
        """)

        change_connection_state(ice_agent, :failed)

      ice_agent.gathering_state == :complete and ice_agent.local_cands == %{} ->
        Logger.debug("""
        There are no local candidates and there won't be any new ones. Changning connection state to failed.
        """)

        change_connection_state(ice_agent, :failed)

      true ->
        ice_agent
    end
  end

  # credo:disable-for-next-line Credo.Check.Refactor.CyclomaticComplexity
  defp update_connection_state(%__MODULE__{state: :connected} = ice_agent) do
    cond do
      ice_agent.eoc == true and ice_agent.gathering_state == :complete and
        Checklist.get_valid_pair(ice_agent.checklist) == nil and
          Checklist.finished?(ice_agent.checklist) ->
        change_connection_state(ice_agent, :failed)

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
      ice_agent.role == :controlled and ice_agent.eoc == true and
        ice_agent.gathering_state == :complete and
        ice_agent.selected_pair != nil and Checklist.finished?(ice_agent.checklist) ->
        Logger.debug("""
        Finished all conn checks, there won't be any further local or remote candidates
        and we have selected pair. Changing connection state to completed.
        """)

        change_connection_state(ice_agent, :completed)

      ice_agent.role == :controlling and ice_agent.selected_pair != nil ->
        change_connection_state(ice_agent, :completed)

      ice_agent.role == :controlling and match?({true, _pair_id}, ice_agent.nominating?) and
          Map.fetch!(ice_agent.checklist, elem(ice_agent.nominating?, 1)).state == :failed ->
        {_, pair_id} = ice_agent.nominating?

        Logger.debug("""
        Pair we tried to nominate failed. Changing connection state to failed. \
        Pair id: #{pair_id}
        """)

        change_connection_state(ice_agent, :failed)

      Checklist.get_valid_pair(ice_agent.checklist) == nil and ice_agent.local_cands == %{} and
          ice_agent.gathering_state == :complete ->
        Logger.debug("""
        No valid pairs in state connected, no local candidates and gathering state is complete.
        Changing connection state to failed.
        """)

        change_connection_state(ice_agent, :failed)

      Checklist.get_valid_pair(ice_agent.checklist) == nil ->
        Logger.debug("No valid pairs in state connected. Changing connection state to checking.")
        change_connection_state(ice_agent, :checking)

      true ->
        ice_agent
    end
  end

  defp update_connection_state(%__MODULE__{state: :completed} = ice_agent) do
    if ice_agent.selected_pair == nil do
      Logger.debug("""
      No selected pair in state completed. Looks like we lost the selected pair.
      Changing connection state to failed.
      """)

      change_connection_state(ice_agent, :failed)
    else
      ice_agent
    end
  end

  # TODO handle more states
  defp update_connection_state(ice_agent) do
    ice_agent
  end

  defp update_ta_timer(ice_agent) do
    if work_to_do?(ice_agent) do
      if ice_agent.ta_timer != nil do
        # do nothing, timer already works
        ice_agent
      else
        Logger.debug("Starting Ta timer")
        enable_timer(ice_agent)
      end
    else
      if ice_agent.ta_timer != nil do
        Logger.debug("Stopping Ta timer")
        disable_timer(ice_agent)
      else
        # do nothing, timer already stopped
        ice_agent
      end
    end
  end

  defp work_to_do?(ice_agent) when ice_agent.state in [:completed, :failed], do: false

  defp work_to_do?(ice_agent) do
    gath_trans_in_progress? =
      Enum.any?(ice_agent.gathering_transactions, fn {_id, %{state: t_state}} ->
        t_state in [:waiting, :in_progress]
      end)

    not Checklist.finished?(ice_agent.checklist) or gath_trans_in_progress?
  end

  defp enable_timer(ice_agent) do
    timer = Process.send_after(self(), :ta_timeout, 0)
    %{ice_agent | ta_timer: timer}
  end

  defp disable_timer(ice_agent) do
    Process.cancel_timer(ice_agent.ta_timer)

    # flush mailbox
    receive do
      :ta_timeout -> :ok
    after
      0 -> :ok
    end

    %{ice_agent | ta_timer: nil}
  end

  defp send_keepalive(ice_agent, pair) do
    type = %Type{class: :indication, method: :binding}

    req =
      type
      |> Message.new()
      |> Message.with_fingerprint()

    dst = {pair.remote_cand.address, pair.remote_cand.port}
    {_result, ice_agent} = do_send(ice_agent, pair.local_cand, dst, Message.encode(req))
    ice_agent
  end

  defp send_conn_check(ice_agent, pair) do
    type = %Type{class: :request, method: :binding}

    role_attr =
      if ice_agent.role == :controlling do
        %ICEControlling{tiebreaker: ice_agent.tiebreaker}
      else
        %ICEControlled{tiebreaker: ice_agent.tiebreaker}
      end

    # priority sent to the other side has to be
    # computed with the candidate type preference of
    # peer-reflexive; refer to sec 7.1.1
    priority = Candidate.priority(:prflx)

    attrs = [
      %Username{value: "#{ice_agent.remote_ufrag}:#{ice_agent.local_ufrag}"},
      %Priority{priority: priority},
      role_attr
    ]

    # we can nominate only when being the controlling agent
    # the controlled agent uses nominate? flag according to 7.3.1.5
    attrs =
      if pair.nominate? and ice_agent.role == :controlling do
        attrs ++ [%UseCandidate{}]
      else
        attrs
      end

    req =
      Message.new(type, attrs)
      |> Message.with_integrity(ice_agent.remote_pwd)
      |> Message.with_fingerprint()

    dst = {pair.remote_cand.address, pair.remote_cand.port}

    case do_send(ice_agent, pair.local_cand, dst, Message.encode(req)) do
      {:ok, ice_agent} ->
        pair = %CandidatePair{pair | state: :in_progress}

        conn_check = %{
          pair_id: pair.id,
          send_time: System.monotonic_time(:millisecond)
        }

        conn_checks = Map.put(ice_agent.conn_checks, req.transaction_id, conn_check)
        checklist = Map.put(ice_agent.checklist, pair.id, pair)
        %__MODULE__{ice_agent | conn_checks: conn_checks, checklist: checklist}

      {:error, ice_agent} ->
        ice_agent
    end
  end

  defp do_send(ice_agent, %cand_mod{} = local_cand, dst, data) do
    {dst_ip, dst_port} = dst

    case cand_mod.send_data(local_cand, dst_ip, dst_port, data) do
      {:ok, local_cand} ->
        ice_agent = put_in(ice_agent.local_cands[local_cand.base.id], local_cand)
        {:ok, ice_agent}

      {:error, reason, local_cand} ->
        Logger.debug("Couldn't send data, reason: #{reason}, cand: #{inspect(local_cand)}")
        ice_agent = put_in(ice_agent.local_cands[local_cand.base.id], local_cand)
        ice_agent = close_candidate(ice_agent, local_cand)
        {:error, ice_agent}
    end
  end

  defp notify(nil, _msg), do: :ok
  defp notify(dst, msg), do: send(dst, {:ex_ice, self(), msg})
end
