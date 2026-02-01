defmodule ExICE.Priv.ICEAgent do
  @moduledoc false

  require Logger

  alias ExICE.Priv.{
    Candidate,
    CandidatePair,
    Checklist,
    ConnCheckHandler,
    Gatherer,
    IfDiscovery,
    Transport,
    Utils
  }

  alias ExICE.Priv.Attribute.{ICEControlling, ICEControlled, Priority, UseCandidate}
  alias ExICE.Priv.Candidate.Srflx

  alias ExSTUN.Message
  alias ExSTUN.Message.Type
  alias ExSTUN.Message.Attribute.{ErrorCode, Username, XORMappedAddress}

  # Ta timeout in ms.
  @ta_timeout 50

  # Transaction timeout in ms.
  # See appendix B.1.
  @hto 2_000

  # Pair timeout in ms.
  # If we don't receive any data in this time,
  # a pair is marked as failed.
  @pair_timeout 8_000

  # End-of-candidates timeout in ms.
  # If we don't receive end-of-candidates indication in this time,
  # we will set it on our own.
  @eoc_timeout 10_000

  # Connectivity check retransmission timeout in ms.
  @tr_rtx_timeout 500

  @conn_check_handler %{
    controlling: ConnCheckHandler.Controlling,
    controlled: ConnCheckHandler.Controlled
  }

  defguardp are_pairs_equal(p1, p2)
            when p1.local_cand_id == p2.local_cand_id and p1.remote_cand_id == p2.remote_cand_id

  defguardp is_response(class) when class in [:success_response, :error_response]

  @type t() :: struct()

  defstruct [
    :controlling_process,
    :on_connection_state_change,
    :on_gathering_state_change,
    :on_data,
    :on_new_candidate,
    :aggressive_nomination,
    :if_discovery_module,
    :transport_module,
    :gatherer,
    :ice_transport_policy,
    :ta_timer,
    :eoc_timer,
    :role,
    :tiebreaker,
    :selected_pair_id,
    :local_ufrag,
    :local_pwd,
    :remote_ufrag,
    :remote_pwd,
    state: :new,
    gathering_transactions: %{},
    checklist: %{},
    conn_checks: %{},
    tr_rtx: [],
    keepalives: %{},
    gathering_state: :new,
    eoc: false,
    # {did we nominate pair, pair id}
    nominating?: {false, nil},
    sockets: [],
    local_cands: %{},
    remote_cands: %{},
    local_preferences: %{},
    stun_servers: [],
    turn_servers: [],
    resolved_turn_servers: [],
    host_to_srflx_ip_mapper: nil,
    # stats
    bytes_sent: 0,
    bytes_received: 0,
    packets_sent: 0,
    packets_received: 0,
    selected_candidate_pair_changes: 0,
    # binding requests that failed to pass checks required to assign them to specific candidate pair
    # e.g. missing required attributes, role conflict, authentication, etc.
    unmatched_requests: 0
  ]

  @spec unmarshal_remote_candidate(String.t()) :: {:ok, Candidate.t()} | {:error, term()}
  def unmarshal_remote_candidate(remote_cand_str) do
    with {_, {:ok, remote_cand}} <- {:unmarshal, ExICE.Candidate.unmarshal(remote_cand_str)},
         {_, {:ok, remote_cand}} <- {:resolve_address, resolve_address(remote_cand)} do
      {:ok, remote_cand}
    else
      {operation, {:error, reason}} -> {:error, {operation, reason}}
    end
  end

  defp resolve_address(remote_cand) when is_binary(remote_cand.address) do
    Logger.debug("Trying to resolve addr: #{remote_cand.address}")

    with pid when is_pid(pid) <- Process.whereis(ExICE.Priv.MDNS.Resolver),
         {:ok, addr} <- ExICE.Priv.MDNS.Resolver.gethostbyname(remote_cand.address) do
      Logger.debug("Successfully resolved #{remote_cand.address} to #{inspect(addr)}")
      remote_cand = %ExICE.Candidate{remote_cand | address: addr}
      {:ok, remote_cand}
    else
      {:error, reason} = err ->
        Logger.debug("Couldn't resolve #{remote_cand.address}, reason: #{reason}")
        err

      nil ->
        Logger.debug("Couldn't resolve #{remote_cand.address}, reason: MDNS reslover not alive.")
        {:error, :mdns_resolver_not_alive}
    end
  end

  defp resolve_address(remote_cand) do
    {:ok, remote_cand}
  end

  @spec new(Keyword.t()) :: t()
  def new(opts) do
    {stun_servers, turn_servers} = parse_ice_servers(opts[:ice_servers] || [])

    {local_ufrag, local_pwd} = generate_credentials()

    controlling_process = Keyword.fetch!(opts, :controlling_process)

    if_discovery_module = opts[:if_discovery_module] || IfDiscovery.Inet
    transport_module = opts[:transport_module] || Transport.UDP
    ip_filter = opts[:ip_filter] || fn _ -> true end
    ports = opts[:ports] || [0]

    start_pair_timer()

    %__MODULE__{
      controlling_process: controlling_process,
      on_connection_state_change: opts[:on_connection_state_change] || controlling_process,
      on_gathering_state_change: opts[:on_gathering_state_change] || controlling_process,
      on_data: opts[:on_data] || controlling_process,
      on_new_candidate: opts[:on_new_candidate] || controlling_process,
      aggressive_nomination: Keyword.get(opts, :aggressive_nomination, false),
      if_discovery_module: if_discovery_module,
      transport_module: transport_module,
      gatherer: Gatherer.new(if_discovery_module, transport_module, ip_filter, ports),
      ice_transport_policy: opts[:ice_transport_policy] || :all,
      role: opts[:role],
      tiebreaker: generate_tiebreaker(),
      local_ufrag: local_ufrag,
      local_pwd: local_pwd,
      stun_servers: stun_servers,
      turn_servers: turn_servers,
      host_to_srflx_ip_mapper: opts[:host_to_srflx_ip_mapper]
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

  @spec get_role(t()) :: ExICE.Agent.role() | nil
  def get_role(ice_agent), do: ice_agent.role

  @spec get_local_credentials(t()) :: {binary(), binary()}
  def get_local_credentials(ice_agent) do
    {ice_agent.local_ufrag, ice_agent.local_pwd}
  end

  @spec get_local_candidates(t()) :: [binary()]
  def get_local_candidates(ice_agent) do
    Enum.map(ice_agent.local_cands, fn {_id, %cand_mod{} = cand} ->
      cand_mod.marshal(cand)
    end)
  end

  @spec get_remote_candidates(t()) :: [binary()]
  def get_remote_candidates(ice_agent) do
    Enum.map(ice_agent.remote_cands, fn {_id, cand} -> ExICE.Candidate.marshal(cand) end)
  end

  @spec get_stats(t()) :: map()
  def get_stats(ice_agent) do
    local_cands =
      ice_agent.local_cands
      |> Map.values()
      |> Enum.map(fn %cand_mod{} = cand -> cand_mod.to_candidate(cand) end)

    remote_cands = Map.values(ice_agent.remote_cands)

    candidate_pairs =
      ice_agent.checklist
      |> Map.values()
      |> Enum.map(&CandidatePair.to_candidate_pair(&1))

    %{
      bytes_sent: ice_agent.bytes_sent,
      bytes_received: ice_agent.bytes_received,
      packets_sent: ice_agent.packets_sent,
      packets_received: ice_agent.packets_received,
      unmatched_requests: ice_agent.unmatched_requests,
      selected_candidate_pair_changes: ice_agent.selected_candidate_pair_changes,
      state: ice_agent.state,
      role: ice_agent.role,
      local_ufrag: ice_agent.local_ufrag,
      local_candidates: local_cands,
      remote_candidates: remote_cands,
      candidate_pairs: candidate_pairs
    }
  end

  @spec set_role(t(), ExICE.ICEAgent.role()) :: t()
  def set_role(%__MODULE__{state: :closed} = ice_agent, _) do
    Logger.debug("Tried to set role in closed state. Ignoring.")
    ice_agent
  end

  def set_role(%__MODULE__{role: nil} = ice_agent, role) do
    %__MODULE__{ice_agent | role: role}
  end

  def set_role(%__MODULE__{} = ice_agent, _role) do
    Logger.warning("Can't set role. Role already set. Ignoring.")
    ice_agent
  end

  @spec set_remote_credentials(t(), binary(), binary()) :: t()
  def set_remote_credentials(%__MODULE__{state: state} = ice_agent, _, _)
      when state in [:failed, :closed] do
    Logger.debug("Tried to set remote credentials in state #{state}. Ignoring.")
    ice_agent
  end

  def set_remote_credentials(
        %__MODULE__{remote_ufrag: nil, remote_pwd: nil} = ice_agent,
        ufrag,
        pwd
      ) do
    Logger.debug("Setting remote credentials: #{inspect(ufrag)}:#{inspect(pwd)}")
    # This is very loosely based on RFC 8863, sec. 4.
    # We can start eoc timer after sending and receiving ICE credentials.
    # In our case, we do this just after receiving remote credentials.
    %__MODULE__{ice_agent | remote_ufrag: ufrag, remote_pwd: pwd}
    |> start_eoc_timer()
    # check if timer does not need to be started
    |> update_ta_timer()
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
  def gather_candidates(%__MODULE__{state: state} = ice_agent) when state in [:failed, :closed] do
    Logger.warning("Can't gather candidates in state #{state}. Ignoring.")
    ice_agent
  end

  def gather_candidates(%__MODULE__{role: nil} = ice_agent) do
    Logger.warning("Can't gather candidates without role. Set the role with `set_role/2`.")
    ice_agent
  end

  def gather_candidates(%__MODULE__{gathering_state: :gathering} = ice_agent) do
    Logger.warning("Can't gather candidates. Gathering already in progress. Ignoring.")
    ice_agent
  end

  def gather_candidates(%__MODULE__{gathering_state: :complete} = ice_agent) do
    Logger.warning("Can't gather candidates. ICE restart needed. Ignoring.")
    ice_agent
  end

  def gather_candidates(
        %__MODULE__{gathering_state: :new, ice_transport_policy: :all} = ice_agent
      ) do
    ice_agent = change_gathering_state(ice_agent, :gathering)

    {:ok, sockets} = Gatherer.open_sockets(ice_agent.gatherer)

    {local_preferences, host_cands} =
      Gatherer.gather_host_candidates(ice_agent.gatherer, ice_agent.local_preferences, sockets)

    ice_agent = %__MODULE__{ice_agent | local_preferences: local_preferences}

    srflx_cands =
      Gatherer.fabricate_srflx_candidates(
        host_cands,
        ice_agent.host_to_srflx_ip_mapper,
        ice_agent.local_preferences
      )

    ice_agent =
      Enum.reduce(host_cands, ice_agent, fn host_cand, ice_agent ->
        add_local_cand(ice_agent, host_cand)
      end)

    ice_agent =
      Enum.reduce(srflx_cands, ice_agent, fn cand, ice_agent ->
        # don't pair reflexive candidate, it should be pruned anyway - see sec. 6.1.2.4
        put_in(ice_agent.local_cands[cand.base.id], cand)
      end)

    for %cand_mod{} = cand <- host_cands ++ srflx_cands do
      notify(ice_agent.on_new_candidate, {:new_candidate, cand_mod.marshal(cand)})
    end

    srflx_gathering_transactions =
      create_srflx_gathering_transactions(ice_agent.stun_servers, sockets)

    relay_gathering_transactions =
      create_relay_gathering_transactions(ice_agent, ice_agent.turn_servers, sockets)

    gathering_transactions = Map.merge(srflx_gathering_transactions, relay_gathering_transactions)

    %{
      ice_agent
      | sockets: sockets,
        gathering_transactions: gathering_transactions
    }
    |> update_gathering_state()
    |> update_ta_timer()
  end

  def gather_candidates(
        %__MODULE__{gathering_state: :new, ice_transport_policy: :relay} = ice_agent
      ) do
    ice_agent = change_gathering_state(ice_agent, :gathering)

    {:ok, sockets} = Gatherer.open_sockets(ice_agent.gatherer)

    relay_gathering_transactions =
      create_relay_gathering_transactions(ice_agent, ice_agent.turn_servers, sockets)

    %{
      ice_agent
      | sockets: sockets,
        gathering_transactions: relay_gathering_transactions
    }
    |> update_gathering_state()
    |> update_ta_timer()
  end

  @spec add_remote_candidate(t(), Candidate.t()) :: t()
  def add_remote_candidate(%__MODULE__{state: state} = ice_agent, _)
      when state in [:failed, :closed] do
    # Completed state will be caught by the next clause
    Logger.debug("Can't add remote candidate in state #{state}. Ignoring.")
    ice_agent
  end

  def add_remote_candidate(%__MODULE__{eoc: true} = ice_agent, remote_cand) do
    Logger.warning("""
    Can't add remote candidate after end-of-candidates. Ignoring. \
    Candidate: #{inspect(remote_cand)}\
    """)

    ice_agent
  end

  def add_remote_candidate(%__MODULE__{role: nil} = ice_agent, remote_cand) do
    Logger.warning("""
    Can't add remote candidate without role. \
    Set the role with `set_role/2`. Ignoring. \
    Candidate: #{inspect(remote_cand)}
    """)

    ice_agent
  end

  def add_remote_candidate(
        %__MODULE__{remote_ufrag: nil, remote_pwd: nil} = ice_agent,
        remote_cand
      ) do
    Logger.warning("""
    Can't add remote candidate without remote credentials. \
    Set remote credentials with `set_remote_credentials/3`. Ignoring. \
    Candidate: #{inspect(remote_cand)}\
    """)

    ice_agent
  end

  def add_remote_candidate(ice_agent, remote_cand) do
    Logger.debug("Trying to add a new remote candidate: #{inspect(remote_cand)}")

    found_cand =
      find_remote_cand(Map.values(ice_agent.remote_cands), remote_cand.address, remote_cand.port)

    case found_cand do
      nil ->
        ice_agent = do_add_remote_candidate(ice_agent, remote_cand)
        Logger.debug("Successfully added remote candidate.")

        ice_agent
        |> update_connection_state()
        |> update_ta_timer()

      %ExICE.Candidate{type: :prflx} ->
        # if there already is such candidate but discovered via received
        # binding request (i.e. this is prflx candidate), update its type
        # and priority, and update also pairs and potentially selected pair
        Logger.debug(
          "Remote candidate already discovered as prflx. Updating its type and priority. Recomputing pair prios."
        )

        found_cand = %ExICE.Candidate{found_cand | type: :host, priority: remote_cand.priority}
        ice_agent = put_in(ice_agent.remote_cands[found_cand.id], found_cand)
        checklist = recompute_pair_prios(ice_agent)
        ice_agent = %__MODULE__{ice_agent | checklist: checklist}

        if ice_agent.selected_pair_id != nil do
          %CandidatePair{} = best_valid_pair = Checklist.get_valid_pair(ice_agent.checklist)

          if best_valid_pair.id != ice_agent.selected_pair_id do
            Logger.debug("New best valid pair: #{best_valid_pair.id}. Selecting.")

            %__MODULE__{
              ice_agent
              | selected_pair_id: best_valid_pair.id,
                selected_candidate_pair_changes: ice_agent.selected_candidate_pair_changes + 1
            }
          else
            ice_agent
          end
        else
          ice_agent
        end

      %ExICE.Candidate{} ->
        Logger.debug("Duplicated remote candidate. Ignoring. Candidate: #{inspect(remote_cand)}")
        ice_agent
    end
  end

  @spec end_of_candidates(t()) :: t()
  def end_of_candidates(%__MODULE__{state: state} = ice_agent) when state in [:failed, :closed] do
    Logger.debug("Can't set end-of-candidates flag in state #{state}. Ignoring.")
    ice_agent
  end

  def end_of_candidates(%__MODULE__{role: :controlled} = ice_agent) do
    Logger.debug("Setting end-of-candidates flag.")
    ice_agent = %{ice_agent | eoc: true}
    # we might need to move to the completed state
    update_connection_state(ice_agent)
  end

  def end_of_candidates(%__MODULE__{role: :controlling, aggressive_nomination: true} = ice_agent) do
    Logger.debug("Setting end-of-candidates flag")
    ice_agent = %{ice_agent | eoc: true}
    # we might need to move to the completed state
    update_connection_state(ice_agent)
  end

  def end_of_candidates(%__MODULE__{role: :controlling} = ice_agent) do
    Logger.debug("Setting end-of-candidates flag.")
    ice_agent = %{ice_agent | eoc: true}
    # check whether it's time to nominate and if yes, try noimnate
    ice_agent
    |> maybe_nominate()
    |> update_connection_state()
  end

  @spec send_data(t(), binary()) :: t()
  def send_data(%__MODULE__{state: state} = ice_agent, data)
      when state in [:connected, :completed] do
    %CandidatePair{} =
      pair =
      Map.get(ice_agent.checklist, ice_agent.selected_pair_id) ||
        Checklist.get_valid_pair(ice_agent.checklist)

    local_cand = Map.fetch!(ice_agent.local_cands, pair.local_cand_id)
    remote_cand = Map.fetch!(ice_agent.remote_cands, pair.remote_cand_id)

    dst = {remote_cand.address, remote_cand.port}
    data_size = byte_size(data)

    case do_send(ice_agent, local_cand, dst, data) do
      {:ok, ice_agent} ->
        pair = Map.fetch!(ice_agent.checklist, pair.id)

        pair = %CandidatePair{
          pair
          | packets_sent: pair.packets_sent + 1,
            bytes_sent: pair.bytes_sent + data_size
        }

        ice_agent =
          %{
            ice_agent
            | bytes_sent: ice_agent.bytes_sent + data_size,
              packets_sent: ice_agent.packets_sent + 1
          }

        put_in(ice_agent.checklist[pair.id], pair)

      {:error, ice_agent} ->
        pair = Map.fetch!(ice_agent.checklist, pair.id)

        pair = %CandidatePair{
          pair
          | packets_discarded_on_send: pair.packets_discarded_on_send + 1,
            bytes_discarded_on_send: pair.bytes_discarded_on_send + data_size
        }

        put_in(ice_agent.checklist[pair.id], pair)
    end
  end

  def send_data(%__MODULE__{state: state} = ice_agent, _data) do
    Logger.debug("""
    Cannot send data in ICE state: #{inspect(state)}. \
    Data can only be sent in state :connected or :completed. Ignoring.\
    """)

    ice_agent
  end

  @spec restart(t()) :: t()
  def restart(%__MODULE__{state: :closed} = ice_agent) do
    Logger.debug("Can't restart ICE in state closed. Ignoring.")
    ice_agent
  end

  def restart(ice_agent) do
    Logger.debug("Restarting ICE")
    do_restart(ice_agent)
  end

  @spec handle_ta_timeout(t()) :: t()
  def handle_ta_timeout(%__MODULE__{state: :closed} = ice_agent) do
    Logger.debug("Ta timer fired in closed state. Ignoring.")
    ice_agent
  end

  def handle_ta_timeout(%__MODULE__{state: state} = ice_agent)
      when state in [:completed, :failed] do
    Logger.warning("""
    Ta timer fired in unexpected state: #{state}.
    Trying to update gathering and connection states.
    """)

    ice_agent
    |> update_gathering_state()
    |> update_connection_state()
    |> update_ta_timer()
  end

  def handle_ta_timeout(ice_agent) do
    ice_agent =
      ice_agent
      |> timeout_pending_transactions()
      |> update_gathering_state()
      |> update_connection_state()
      |> maybe_nominate()
      |> update_connection_state()

    if ice_agent.state in [:completed, :failed] do
      update_ta_timer(ice_agent)
    else
      ice_agent =
        case find_next_transaction(ice_agent) do
          nil ->
            Logger.debug("No transaction to execute. Did Ta timer fired without the need?")
            ice_agent

          {type, tr} ->
            ice_agent
            |> execute_transaction(type, tr)
            |> update_connection_state()
        end

      # schedule next check and call update_ta_timer
      # if the next check is not needed, update_ta_timer will
      # cancel it
      ta_timer = Process.send_after(self(), :ta_timeout, @ta_timeout)
      ice_agent = %{ice_agent | ta_timer: ta_timer}
      update_ta_timer(ice_agent)
    end
  end

  defp find_next_transaction(ice_agent) do
    find_next_transaction(ice_agent, :conn_check)
  end

  defp find_next_transaction(%{remote_ufrag: nil, remote_pwd: nil} = ice_agent, :conn_check) do
    find_next_transaction(ice_agent, :gathering)
  end

  defp find_next_transaction(ice_agent, :conn_check) do
    case Checklist.get_next_pair(ice_agent.checklist) do
      nil -> find_next_transaction(ice_agent, :gathering)
      pair -> {:conn_check, pair}
    end
  end

  defp find_next_transaction(ice_agent, :gathering) do
    case get_next_gathering_transaction(ice_agent) do
      nil -> find_next_transaction(ice_agent, :rtx)
      {_id, gather_tr} -> {:gathering, gather_tr}
    end
  end

  defp find_next_transaction(ice_agent, :rtx) do
    case List.first(ice_agent.tr_rtx) do
      nil -> nil
      tr_id -> {:rtx, tr_id}
    end
  end

  defp execute_transaction(ice_agent, :conn_check, pair) do
    Logger.debug("Sending conn check on pair: #{inspect(pair.id)}")
    pair = %CandidatePair{pair | last_seen: now()}
    send_conn_check(ice_agent, pair)
  end

  defp execute_transaction(ice_agent, :gathering, tr) do
    {_, ice_agent} = execute_gathering_transaction(ice_agent, tr)
    ice_agent
  end

  defp execute_transaction(ice_agent, :rtx, t_id)
       when is_map_key(ice_agent.gathering_transactions, t_id) do
    Logger.debug("Retransmitting srflx gathering transaction: #{t_id}")

    tr_rtx = List.delete(ice_agent.tr_rtx, t_id)
    ice_agent = %{ice_agent | tr_rtx: tr_rtx}
    tr = Map.fetch!(ice_agent.gathering_transactions, t_id)

    # gather_srflx_candidate will create exactly the same message
    case Gatherer.gather_srflx_candidate(ice_agent.gatherer, t_id, tr.socket, tr.stun_server.url) do
      :ok ->
        Process.send_after(self(), {:tr_rtx_timeout, t_id}, @tr_rtx_timeout)
        ice_agent

      {:error, reason} ->
        Logger.debug("""
        Failed to retransmit srflx gathering transaction, reason: #{inspect(reason)}.
        Transaction id: #{t_id}.
        Scheduling next rtx.\
        """)

        Process.send_after(self(), {:tr_rtx_timeout, t_id}, @tr_rtx_timeout)
        ice_agent
    end
  end

  defp execute_transaction(ice_agent, :rtx, t_id) when is_map_key(ice_agent.conn_checks, t_id) do
    Logger.debug("Retransmitting conn check: #{t_id}")

    tr_rtx = List.delete(ice_agent.tr_rtx, t_id)
    ice_agent = %{ice_agent | tr_rtx: tr_rtx}
    conn_check = Map.fetch!(ice_agent.conn_checks, t_id)

    pair = Map.fetch!(ice_agent.checklist, conn_check.pair_id)
    local_cand = Map.fetch!(ice_agent.local_cands, pair.local_cand_id)
    remote_cand = Map.fetch!(ice_agent.remote_cands, pair.remote_cand_id)
    dst = {remote_cand.address, remote_cand.port}

    case do_send(ice_agent, local_cand, dst, conn_check.raw_req) do
      {:ok, ice_agent} ->
        # retransmissions are not counted in requests sent
        Process.send_after(self(), {:tr_rtx_timeout, t_id}, @tr_rtx_timeout)
        ice_agent

      {:error, ice_agent} ->
        pair = Map.fetch!(ice_agent.checklist, pair.id)

        pair = %CandidatePair{
          pair
          | packets_discarded_on_send: pair.packets_discarded_on_send + 1,
            bytes_discarded_on_send: pair.bytes_discarded_on_send + byte_size(conn_check.raw_req)
        }

        put_in(ice_agent.checklist[pair.id], pair)
    end
  end

  defp execute_transaction(ice_agent, :rtx, t_id) do
    Logger.debug("""
    Tried to retransmit transaction but it is no longer in-progress. Ignoring.
    Transaction id: #{t_id}\
    """)

    tr_rtx = List.delete(ice_agent.tr_rtx, t_id)
    %{ice_agent | tr_rtx: tr_rtx}
  end

  @spec handle_tr_rtx_timeout(t(), integer()) :: t()
  def handle_tr_rtx_timeout(%__MODULE__{state: :closed} = ice_agent, _) do
    Logger.debug("Transaction rtx timer fired in state closed. Ignoring.")
    ice_agent
  end

  def handle_tr_rtx_timeout(ice_agent, t_id) when is_map_key(ice_agent.conn_checks, t_id) do
    # Mark transaction id as ready to be retransmitted.
    # We will do this in handle_ta_timeout as it has to be paced.
    Logger.debug("""
    Scheduling conn check for retransmission.
    Conn check transaction id:  #{t_id}\
    """)

    %{ice_agent | tr_rtx: ice_agent.tr_rtx ++ [t_id]}
  end

  def handle_tr_rtx_timeout(ice_agent, t_id)
      when is_map_key(ice_agent.gathering_transactions, t_id) do
    Logger.debug("""
    Scheduling srflx gathering transaction for retransmission.
    Transaction id: #{t_id}\
    """)

    %{ice_agent | tr_rtx: ice_agent.tr_rtx ++ [t_id]}
  end

  def handle_tr_rtx_timeout(ice_agent, transaction_id) do
    Logger.debug("""
    Transaction timeout timer fired but there is no such transaction in progress. Ignoring.
    Transaction id: #{transaction_id}\
    """)

    ice_agent
  end

  @spec handle_eoc_timeout(t()) :: t()
  def handle_eoc_timeout(%__MODULE__{state: state} = ice_agent)
      when state in [:failed, :closed] do
    Logger.debug("EOC timer fired but we are in the #{state} state. Ignoring.")
    %{ice_agent | eoc_timer: nil}
  end

  def handle_eoc_timeout(%{eoc: true} = ice_agent) do
    Logger.debug("EOC timer fired but EOC flag is already set. Ignoring.")
    %{ice_agent | eoc_timer: nil}
  end

  def handle_eoc_timeout(ice_agent) do
    Logger.debug("EOC timer fired. Setting EOC flag.")
    ice_agent = %{ice_agent | eoc_timer: nil, eoc: true}
    update_connection_state(ice_agent)
  end

  @spec handle_pair_timeout(t()) :: t()
  def handle_pair_timeout(%__MODULE__{state: :closed} = ice_agent) do
    Logger.debug("Pair timer fired in closed state. Ignoring.")
    ice_agent
  end

  def handle_pair_timeout(ice_agent) do
    start_pair_timer()

    # only take final pairs i.e. those that are actually used
    pairs =
      ice_agent.checklist
      |> Map.values()
      |> Stream.filter(fn pair -> pair.state == :succeeded end)
      |> Enum.filter(fn pair -> pair.id == pair.discovered_pair_id end)

    timeout_pairs(ice_agent, pairs, now())
    |> update_connection_state()
  end

  defp timeout_pairs(ice_agent, [], _now), do: ice_agent

  defp timeout_pairs(ice_agent, [%{last_seen: nil} | pairs], now) do
    timeout_pairs(ice_agent, pairs, now)
  end

  defp timeout_pairs(ice_agent, [pair | pairs], now) do
    diff = now - pair.last_seen

    if diff >= @pair_timeout do
      Logger.debug("""
      Pair: #{pair.id} didn't receive any data in #{diff}ms. \
      Marking as failed.\
      """)

      checklist = Checklist.timeout_pairs(ice_agent.checklist, [pair.id, pair.succeeded_pair_id])
      ice_agent = %{ice_agent | checklist: checklist}

      ice_agent =
        if ice_agent.selected_pair_id == pair.id do
          %{
            ice_agent
            | selected_pair_id: nil,
              selected_candidate_pair_changes: ice_agent.selected_candidate_pair_changes + 1
          }
        else
          ice_agent
        end

      timeout_pairs(ice_agent, pairs, now)
    else
      timeout_pairs(ice_agent, pairs, now)
    end
  end

  @spec handle_keepalive_timeout(t(), integer()) :: t()
  def handle_keepalive_timeout(%__MODULE__{state: :closed} = ice_agent, _) do
    Logger.debug("Keepalive timer fired in closed state. Ignoring.")
    ice_agent
  end

  def handle_keepalive_timeout(%__MODULE__{selected_pair_id: id} = ice_agent, id) do
    # if pair was selected, send keepalives only on that pair
    s_pair = Map.fetch!(ice_agent.checklist, id)
    pair = CandidatePair.schedule_keepalive(s_pair)
    ice_agent = %__MODULE__{ice_agent | checklist: Map.put(ice_agent.checklist, id, pair)}
    send_keepalive(ice_agent, ice_agent.checklist[id])
  end

  def handle_keepalive_timeout(%__MODULE__{selected_pair_id: s_pair_id} = ice_agent, _id)
      when not is_nil(s_pair_id) do
    # note: current implementation assumes that, if selected pair exists, none of the already existing
    # valid pairs will ever become selected (only new appearing valid pairs)
    # that's why there's no call to `CandidatePair.schedule_keepalive/1`
    ice_agent
  end

  def handle_keepalive_timeout(ice_agent, id) do
    # TODO: keepalives should be sent only if no data has been sent for @tr_timeout
    # atm, we send keepalives anyways, also it might be better to pace them with ta_timer
    # TODO: candidates not in a valid pair also should be kept alive (RFC 8445, sect 5.1.1.4)
    case Map.fetch(ice_agent.checklist, id) do
      {:ok, %CandidatePair{state: :succeeded, valid?: true} = pair} ->
        pair = CandidatePair.schedule_keepalive(pair)
        ice_agent = %__MODULE__{ice_agent | checklist: Map.put(ice_agent.checklist, id, pair)}
        send_keepalive(ice_agent, pair)

      {:ok, _pair} ->
        ice_agent

      :error when ice_agent.state in [:failed, :completed] ->
        Logger.warning("""
        Received keepalive request for non-existant candidate pair but we are in state: #{ice_agent.state}. \
        Ignoring.\
        """)

        ice_agent

      :error ->
        Logger.warning("Received keepalive request for non-existent candidate pair. Ignoring.")
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
  def handle_udp(%{state: state} = ice_agent, _socket, _src_ip, _src_port, _packet)
      when state in [:failed, :closed] do
    ice_agent
  end

  def handle_udp(ice_agent, socket, src_ip, src_port, packet) do
    turn_tr_id = {socket, {src_ip, src_port}}
    turn_tr = Map.get(ice_agent.gathering_transactions, turn_tr_id)

    cond do
      # if we are still in a process of creating a relay candidate
      # and we received a message from a turn server
      turn_tr != nil and turn_tr.state == :in_progress ->
        handle_turn_gathering_transaction_response(ice_agent, turn_tr_id, turn_tr, packet)

      from_turn?(ice_agent, src_ip, src_port) ->
        handle_turn_message_raw(ice_agent, socket, src_ip, src_port, packet)

      ExSTUN.stun?(packet) ->
        handle_stun_message_raw(ice_agent, socket, src_ip, src_port, packet)

      true ->
        handle_data_message_raw(ice_agent, socket, src_ip, src_port, packet)
    end
  end

  @spec handle_ex_turn_msg(t(), reference(), ExTURN.Client.notification_message()) :: t()
  def handle_ex_turn_msg(%__MODULE__{state: :closed} = ice_agent, _, _) do
    Logger.debug("Received ex_turn message in closed state. Ignoring.")
    ice_agent
  end

  def handle_ex_turn_msg(ice_agent, client_ref, msg) do
    tr_id_tr = find_gathering_transaction(ice_agent.gathering_transactions, client_ref)

    cand = find_relay_cand_by_client(Map.values(ice_agent.local_cands), client_ref)

    case {tr_id_tr, cand} do
      {nil, nil} ->
        ice_agent

      {{tr_id, tr}, nil} ->
        case ExTURN.Client.handle_message(tr.client, msg) do
          {:ok, client} ->
            tr = %{tr | client: client}
            put_in(ice_agent.gathering_transactions[tr_id], tr)

          {:send, dst, data, client} ->
            tr = %{tr | client: client}

            case ice_agent.transport_module.send(tr.socket, dst, data) do
              :ok ->
                put_in(ice_agent.gathering_transactions[tr_id], tr)

              {:error, reason} ->
                Logger.debug(
                  "Failed to send TURN message: #{inspect(reason)}. Closing transaction."
                )

                {_, ice_agent} = pop_in(ice_agent.gathering_transactions[tr_id])
                update_gathering_state(ice_agent)
            end

          {:error, _reason, _client} ->
            {_, ice_agent} = pop_in(ice_agent.gathering_transactions[tr_id])
            update_gathering_state(ice_agent)
        end

      {nil, %{client: %{state: :error}}} ->
        ice_agent

      {nil, cand} ->
        case ExTURN.Client.handle_message(cand.client, msg) do
          {:ok, client} ->
            cand = %{cand | client: client}
            put_in(ice_agent.local_cands[cand.base.id], cand)

          {:send, dst, data, client} ->
            cand = %{cand | client: client}
            ice_agent = put_in(ice_agent.local_cands[cand.base.id], cand)
            # we can't use do_send here as it will try to create permission for the turn address
            case ice_agent.transport_module.send(cand.base.socket, dst, data) do
              :ok ->
                ice_agent

              {:error, reason} ->
                Logger.debug(
                  "Failed to send TURN message: #{inspect(reason)}. Closing candidate."
                )

                close_candidate(ice_agent, cand)
            end

          {:error, _reason, client} ->
            Logger.debug("""
            Couldn't handle TURN message on candidate: #{inspect(cand)}. \
            Closing candidate.\
            """)

            cand = %{cand | client: client}
            ice_agent = put_in(ice_agent.local_cands[cand.base.id], cand)
            close_candidate(ice_agent, cand)
        end
    end
  end

  @spec close(t()) :: t()
  def close(%__MODULE__{state: :closed} = ice_agent) do
    ice_agent
  end

  def close(%__MODULE__{} = ice_agent) do
    ice_agent.sockets
    |> Enum.reduce(ice_agent, fn socket, ice_agent -> close_socket(ice_agent, socket) end)
    |> change_gathering_state(:complete, notify: false)
    |> change_connection_state(:closed, notify: false)
  end

  ## PRIV API

  defp create_srflx_gathering_transactions(stun_servers, sockets) do
    for stun_server <- stun_servers, socket <- sockets, into: %{} do
      <<t_id::12*8>> = :crypto.strong_rand_bytes(12)

      t = %{
        t_id: t_id,
        socket: socket,
        stun_server: stun_server,
        send_time: nil,
        state: :waiting
      }

      {t_id, t}
    end
  end

  defp create_relay_gathering_transactions(ice_agent, turn_servers, sockets) do
    # TODO revisit this
    for turn_server <- turn_servers, socket <- sockets do
      with {:ok, client} <-
             ExTURN.Client.new(turn_server.url, turn_server.username, turn_server.credential),
           {:ok, {sock_ip, _sock_port}} <- ice_agent.transport_module.sockname(socket),
           {true, _, _} <-
             {Utils.family(client.turn_ip) == Utils.family(sock_ip), client, sock_ip} do
        t_id = {socket, {client.turn_ip, client.turn_port}}

        t = %{
          t_id: t_id,
          socket: socket,
          client: client,
          send_time: nil,
          state: :waiting
        }

        {t_id, t}
      else
        {false, client, sock_ip} ->
          Logger.debug("""
          TURN's IP family doesn't match socket's IP family.
          TURN: #{inspect(turn_server)}.
          TURN IP: #{inspect(client.turn_ip)}.
          Socket IP: #{inspect(sock_ip)}.
          Ignoring.
          """)

          {nil, nil}

        other ->
          Logger.warning("Couldn't create TURN client: #{inspect(other)}. Ignoring.")
          {nil, nil}
      end
    end
    |> Enum.reject(fn {tr_id, tr} -> tr_id == nil and tr == nil end)
    |> Map.new()
  end

  defp do_add_remote_candidate(ice_agent, remote_cand) when ice_agent.local_cands == %{} do
    Logger.debug("Not adding any new pairs as we don't have any local candidates.")

    %__MODULE__{
      ice_agent
      | remote_cands: Map.put(ice_agent.remote_cands, remote_cand.id, remote_cand)
    }
  end

  defp do_add_remote_candidate(ice_agent, remote_cand) do
    local_cands = get_matching_candidates_remote(Map.values(ice_agent.local_cands), remote_cand)

    checklist_foundations = get_foundations(ice_agent)

    # See RFC 8445 sec. 6.1.2.4
    # "For each pair where the local candidate is reflexive, the candidate
    # MUST be replaced by its base."
    # I belive that this is the same as filtering srflx candidates out.
    # Libnice seems to do the same.
    new_pairs =
      local_cands
      |> Enum.reject(fn %mod{} -> mod == Srflx end)
      |> Map.new(fn local_cand ->
        pair_state = get_pair_state(local_cand, remote_cand, checklist_foundations)
        pair = CandidatePair.new(local_cand, remote_cand, ice_agent.role, pair_state)
        {pair.id, pair}
      end)

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
        remote_cands: Map.put(ice_agent.remote_cands, remote_cand.id, remote_cand)
    }
  end

  defp get_next_gathering_transaction(ice_agent) do
    Enum.find(ice_agent.gathering_transactions, fn {_t_id, t} -> t.state == :waiting end)
  end

  defp execute_gathering_transaction(ice_agent, %{stun_server: stun_server} = tr) do
    {:ok, {sock_ip, sock_port}} = ice_agent.transport_module.sockname(tr.socket)

    Logger.debug("""
    Sending binding request to gather srflx candidate for:
    socket: #{inspect(sock_ip)}:#{sock_port},
    stun_server: #{inspect(stun_server)}
    """)

    case Gatherer.gather_srflx_candidate(ice_agent.gatherer, tr.t_id, tr.socket, stun_server.url) do
      :ok ->
        tr = %{tr | state: :in_progress, send_time: now()}
        gathering_transactions = Map.put(ice_agent.gathering_transactions, tr.t_id, tr)
        ice_agent = %__MODULE__{ice_agent | gathering_transactions: gathering_transactions}
        {:ok, ice_agent}

      {:error, reason} ->
        Logger.debug("Couldn't send binding request, reason: #{reason}")

        {_, ice_agent} = pop_in(ice_agent.gathering_transactions[tr.t_id])
        ice_agent = update_gathering_state(ice_agent)

        {:error, ice_agent}
    end
  end

  defp execute_gathering_transaction(ice_agent, %{client: client} = tr) do
    {:ok, {sock_ip, sock_port}} = ice_agent.transport_module.sockname(tr.socket)

    Logger.debug("""
    Starting the process of gathering relay candidate for:
    socket: #{inspect(sock_ip)}:#{sock_port},
    turn_server: #{inspect(client.turn_ip)}:#{client.turn_port}
    """)

    {:send, turn_addr, data, client} = ExTURN.Client.allocate(client)
    tr = Map.put(tr, :client, client)

    case ice_agent.transport_module.send(tr.socket, turn_addr, data) do
      :ok ->
        tr = %{tr | state: :in_progress, send_time: now()}
        ice_agent = put_in(ice_agent.gathering_transactions[tr.t_id], tr)
        ice_agent = update_gathering_state(ice_agent)
        {:ok, ice_agent}

      {:error, reason} ->
        Logger.debug("Couldn't send allocate request, reason: #{reason}")

        {_, ice_agent} = pop_in(ice_agent.gathering_transactions[tr.t_id])
        ice_agent = update_gathering_state(ice_agent)

        {:error, ice_agent}
    end
  end

  defp timeout_pending_transactions(ice_agent) do
    now = now()
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
      Enum.split_with(ice_agent.gathering_transactions, fn {_id, tr} ->
        tr.state == :in_progress and now - tr.send_time >= @hto
      end)

    gath_trans = Map.new(gath_trans)

    if stale_gath_trans != [] do
      ids = Enum.map(stale_gath_trans, fn {id, _} -> id end)
      Logger.debug("Gathering transactions timed out: #{inspect(ids)}")
    end

    %__MODULE__{ice_agent | gathering_transactions: gath_trans}
  end

  defp from_turn?(ice_agent, src_ip, src_port),
    do: {src_ip, src_port} in ice_agent.resolved_turn_servers

  defp handle_turn_gathering_transaction_response(ice_agent, tr_id, tr, packet) do
    {_socket, {src_ip, src_port}} = tr_id

    case ExTURN.Client.handle_message(tr.client, {:socket_data, src_ip, src_port, packet}) do
      {:ok, client} ->
        tr = %{tr | client: client}
        put_in(ice_agent.gathering_transactions[tr_id], tr)

      {:allocation_created, {alloc_ip, alloc_port}, client} ->
        {_, ice_agent} = pop_in(ice_agent.gathering_transactions[tr_id])

        resolved_turn_servers = [
          {client.turn_ip, client.turn_port} | ice_agent.resolved_turn_servers
        ]

        # Use sock_addr for calculating priority.
        # In other case, we might get duplicates.
        {:ok, {sock_addr, _sock_port}} = ice_agent.transport_module.sockname(tr.socket)

        {local_preferences, priority} =
          Candidate.priority(ice_agent.local_preferences, sock_addr, :relay)

        ice_agent = %{
          ice_agent
          | resolved_turn_servers: resolved_turn_servers,
            local_preferences: local_preferences
        }

        relay_cand =
          Candidate.Relay.new(
            address: alloc_ip,
            port: alloc_port,
            base_address: alloc_ip,
            base_port: alloc_port,
            priority: priority,
            transport_module: ice_agent.transport_module,
            socket: tr.socket,
            client: client
          )

        Logger.debug("New relay candidate: #{inspect(relay_cand)}")

        notify(
          ice_agent.on_new_candidate,
          {:new_candidate, Candidate.Relay.marshal(relay_cand)}
        )

        add_local_cand(ice_agent, relay_cand)

      {:send, turn_addr, data, client} ->
        tr = %{tr | client: client}
        :ok = ice_agent.transport_module.send(tr.socket, turn_addr, data)
        put_in(ice_agent.gathering_transactions[tr_id], tr)

      {:error, _reason, _client} ->
        Logger.debug("Failed to create TURN allocation.")
        {_, ice_agent} = pop_in(ice_agent.gathering_transactions[tr_id])
        ice_agent
    end
  end

  defp handle_turn_message_raw(ice_agent, socket, src_ip, src_port, packet) do
    local_cands = Map.values(ice_agent.local_cands)

    case find_relay_cand_by_socket(local_cands, socket) do
      nil ->
        Logger.debug("""
        Couldn't find relay candidate for:
        socket: #{inspect(socket)}
        src address: #{inspect({src_ip, src_port})}.
        Ignoring incoming TURN message.
        """)

        ice_agent

      %{base: %{closed?: false}} = relay_cand ->
        handle_turn_message(ice_agent, relay_cand, src_ip, src_port, packet)

      %{base: %{closed?: true}} = relay_cand ->
        log_closed_cand_message(relay_cand, src_ip, src_port)
        ice_agent
    end
  end

  defp handle_turn_message(ice_agent, %cand_mod{} = cand, src_ip, src_port, packet) do
    case cand_mod.receive_data(cand, src_ip, src_port, packet) do
      {:ok, cand} ->
        put_in(ice_agent.local_cands[cand.base.id], cand)

      {:ok, src_ip, src_port, packet, cand} ->
        ice_agent = put_in(ice_agent.local_cands[cand.base.id], cand)

        if ExSTUN.stun?(packet) do
          case ExSTUN.Message.decode(packet) do
            {:ok, msg} ->
              do_handle_stun_message(ice_agent, cand, src_ip, src_port, msg)

            {:error, reason} ->
              Logger.warning("Couldn't decode stun message: #{inspect(reason)}")
              ice_agent
          end
        else
          remote_cand = find_remote_cand(Map.values(ice_agent.remote_cands), src_ip, src_port)
          pair = Checklist.find_pair(ice_agent.checklist, cand.base.id, remote_cand.id)
          handle_data_message(ice_agent, pair, packet)
        end

      {:error, _reason, cand} ->
        Logger.debug("""
        Failed to receive TURN message on candidate: #{inspect(cand)}. \
        Closing candidate.\
        """)

        close_candidate(ice_agent, cand)
    end
  end

  defp handle_stun_message_raw(ice_agent, socket, src_ip, src_port, packet) do
    local_cands = Map.values(ice_agent.local_cands)

    case find_host_cand(local_cands, socket) do
      nil ->
        Logger.debug("""
        Couldn't find host candidate for #{inspect(src_ip)}:#{src_port}. \
        Ignoring incoming STUN message.\
        """)

        ice_agent

      %{base: %{closed?: false}} = host_cand ->
        handle_stun_message(ice_agent, host_cand, src_ip, src_port, packet)

      %{base: %{closed?: true}} = host_cand ->
        log_closed_cand_message(host_cand, src_ip, src_port)
        ice_agent
    end
  end

  defp handle_stun_message(ice_agent, host_cand, src_ip, src_port, packet) do
    case ExSTUN.Message.decode(packet) do
      {:ok, msg} ->
        do_handle_stun_message(ice_agent, host_cand, src_ip, src_port, msg)

      {:error, reason} ->
        Logger.warning("Couldn't decode stun message: #{inspect(reason)}")
        ice_agent
    end
  end

  defp handle_data_message_raw(ice_agent, socket, src_ip, src_port, packet) do
    with remote_cands <- Map.values(ice_agent.remote_cands),
         {:host, %_{base: %{closed?: false}} = local_cand} <-
           {:host, find_host_cand(Map.values(ice_agent.local_cands), socket)},
         {:remote, %_{} = remote_cand} <-
           {:remote, find_remote_cand(remote_cands, src_ip, src_port)} do
      %CandidatePair{} =
        pair = Checklist.find_pair(ice_agent.checklist, local_cand.base.id, remote_cand.id)

      handle_data_message(ice_agent, pair, packet)
    else
      {:host, %{base: %{closed?: true}} = host_cand} ->
        log_closed_cand_message(host_cand, src_ip, src_port)
        ice_agent

      {type, _} ->
        Logger.debug("""
        Couldn't find #{type} candidate for:
        socket: #{inspect(socket)}
        src address: #{inspect({src_ip, src_port})}.
        And this is not a STUN message. Ignoring.
        """)

        ice_agent
    end
  end

  defp handle_data_message(ice_agent, %{state: :succeeded} = pair, packet) do
    # take final pair as local candidate might be srflx
    pair = Map.fetch!(ice_agent.checklist, pair.discovered_pair_id)
    do_handle_data_message(ice_agent, pair, packet)
  end

  defp handle_data_message(ice_agent, %{state: :failed} = pair, packet) do
    Logger.debug("""
    Received data on failed pair. Rescheduling pair for conn check. Pair id: #{pair.id}\
    """)

    ice_agent = do_handle_data_message(ice_agent, pair, packet)

    # re-schedule pair
    pair = %{pair | state: :waiting}
    ice_agent = put_in(ice_agent.checklist[pair.id], pair)
    update_ta_timer(ice_agent)
  end

  # We might receive data on a pair that we haven't check on our side yet.
  defp handle_data_message(ice_agent, pair, packet) do
    do_handle_data_message(ice_agent, pair, packet)
  end

  defp do_handle_data_message(ice_agent, pair, packet) do
    data_size = byte_size(packet)

    pair = %CandidatePair{
      pair
      | last_seen: now(),
        packets_received: pair.packets_received + 1,
        bytes_received: pair.bytes_received + data_size
    }

    ice_agent = put_in(ice_agent.checklist[pair.id], pair)

    notify(ice_agent.on_data, {:data, packet})

    %{
      ice_agent
      | bytes_received: ice_agent.bytes_received + data_size,
        packets_received: ice_agent.packets_received + 1
    }
  end

  defp add_local_cand(ice_agent, local_cand) do
    ice_agent = put_in(ice_agent.local_cands[local_cand.base.id], local_cand)

    remote_cands = get_matching_candidates_local(Map.values(ice_agent.remote_cands), local_cand)

    checklist_foundations = get_foundations(ice_agent)

    new_pairs =
      for remote_cand <- remote_cands, into: %{} do
        pair_state = get_pair_state(local_cand, remote_cand, checklist_foundations)
        pair = CandidatePair.new(local_cand, remote_cand, ice_agent.role, pair_state)
        {pair.id, pair}
      end

    checklist = Checklist.prune(Map.merge(ice_agent.checklist, new_pairs))

    added_pairs = Map.drop(checklist, Map.keys(ice_agent.checklist))

    if added_pairs == %{} and remote_cands != [] do
      Logger.debug("Not adding any new pairs as they were redundant")
    end

    if added_pairs != %{} do
      Logger.debug("New candidate pairs: #{inspect(added_pairs)}")
    end

    %__MODULE__{ice_agent | checklist: checklist}
  end

  defp do_handle_stun_message(ice_agent, local_cand, src_ip, src_port, %Message{} = msg) do
    # TODO revisit 7.3.1.4

    case msg.type do
      %Type{class: :indication, method: :binding} ->
        Logger.debug("""
        Received binding indication from: #{inspect({src_ip, src_port})}, \
        on: #{inspect({local_cand.base.base_address, local_cand.base.base_port})} \
        """)

        handle_binding_indication(ice_agent, local_cand, src_ip, src_port)

      %Type{class: :request, method: :binding} ->
        Logger.debug("""
        Received binding request from: #{inspect({src_ip, src_port})}, \
        on: #{inspect({local_cand.base.base_address, local_cand.base.base_port})} \
        """)

        handle_binding_request(ice_agent, local_cand, src_ip, src_port, msg)

      %Type{class: class, method: :binding}
      when is_response(class) and is_map_key(ice_agent.conn_checks, msg.transaction_id) ->
        Logger.debug("""
        Received conn check response from: #{inspect({src_ip, src_port})}, \
        on: #{inspect({local_cand.base.base_address, local_cand.base.base_port})} \
        """)

        handle_conn_check_response(ice_agent, local_cand, src_ip, src_port, msg)

      %Type{class: class, method: :binding}
      when is_response(class) and is_map_key(ice_agent.gathering_transactions, msg.transaction_id) ->
        Logger.debug("""
        Received gathering transaction response from: #{inspect({src_ip, src_port})}, \
        on: #{inspect({local_cand.base.base_address, local_cand.base.base_port})} \
        """)

        handle_stun_gathering_transaction_response(ice_agent, msg)

      %Type{class: class, method: :binding}
      when is_response(class) and is_map_key(ice_agent.keepalives, msg.transaction_id) ->
        # TODO: this a good basis to implement consent freshness
        handle_keepalive_response(ice_agent, local_cand, src_ip, src_port, msg)

      %Type{class: class, method: :binding} when is_response(class) ->
        Logger.debug("""
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

  defp log_closed_cand_message(local_cand, src_ip, src_port) do
    Logger.debug("""
    Received STUN, TURN or data message on closed candidate: \
    #{local_cand.base.id} #{inspect(local_cand.base.base_address)}:#{local_cand.base.base_port} \
    from #{inspect(src_ip)}:#{src_port}. Ignoring. \
    """)
  end

  ## BINDING INDICATION HANDLING ##
  defp handle_binding_indication(ice_agent, local_cand, src_ip, src_port) do
    remote_cand = find_remote_cand(Map.values(ice_agent.remote_cands), src_ip, src_port)
    pair = Checklist.find_pair(ice_agent.checklist, local_cand.base.id, remote_cand.id)

    case pair.state do
      :succeeded ->
        pair = Map.fetch!(ice_agent.checklist, pair.discovered_pair_id)
        pair = %CandidatePair{pair | last_seen: now()}
        put_in(ice_agent.checklist[pair.id], pair)

      :failed ->
        Logger.debug("""
        Received binding indication on pair that has already been marked as failed. \
        Ignoring. Pair id: #{pair.id}\
        """)

        ice_agent

      _other ->
        # We might receive binding indication on a pair that we haven't checked
        # on our side yet.
        # The `last_seen` field will be overritten when sending conn-check,
        # but we update it for consistency, the same way we update it when
        # receiving normal data.
        pair = %CandidatePair{pair | last_seen: now()}
        put_in(ice_agent.checklist[pair.id], pair)
    end
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

      pair =
        CandidatePair.new(local_cand, remote_cand, ice_agent.role, :waiting, last_seen: now())

      @conn_check_handler[ice_agent.role].handle_conn_check_request(
        ice_agent,
        pair,
        msg,
        use_cand_attr
      )
      # As a result of handling incoming binding request, we might have re-scheduled pair.
      # Hence, we have to update ta timer.
      |> update_ta_timer()
    else
      error ->
        ice_agent = %__MODULE__{ice_agent | unmatched_requests: ice_agent.unmatched_requests + 1}
        handle_binding_request_error(ice_agent, local_cand, src_ip, src_port, msg, error)
    end
  end

  defp handle_binding_request_error(ice_agent, local_cand, src_ip, src_port, msg, error) do
    case error do
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

    ice_agent = %__MODULE__{ice_agent | role: :controlled}

    checklist = recompute_pair_prios(ice_agent)

    {:ok, %__MODULE__{ice_agent | checklist: checklist}}
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

    ice_agent = %__MODULE__{ice_agent | role: :controlling}

    checklist = recompute_pair_prios(ice_agent)

    {:ok, %__MODULE__{ice_agent | checklist: checklist}}
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
    {%{pair_id: pair_id, raw_req: raw_req}, conn_checks} =
      Map.pop!(ice_agent.conn_checks, msg.transaction_id)

    {:ok, req} = Message.decode(raw_req)
    ice_agent = %__MODULE__{ice_agent | conn_checks: conn_checks}
    conn_check_pair = Map.fetch!(ice_agent.checklist, pair_id)

    # This shouldn't happen as we clear conn checks when a pair times out.
    if conn_check_pair.state == :failed do
      raise """
      Received conn check success response on failed pair. \
      This should never happen. \
      Pair: #{inspect(conn_check_pair)}\
      """
    end

    # check that the source and destination transport
    # addresses are symmetric - see sec. 7.2.5.2.1
    if symmetric?(ice_agent, local_cand.base.socket, {src_ip, src_port}, conn_check_pair) do
      case msg.type.class do
        :success_response -> handle_conn_check_success_response(ice_agent, conn_check_pair, msg)
        :error_response -> handle_conn_check_error_response(ice_agent, conn_check_pair, req, msg)
      end
    else
      cc_local_cand = Map.fetch!(ice_agent.local_cands, conn_check_pair.local_cand_id)
      cc_remote_cand = Map.fetch!(ice_agent.remote_cands, conn_check_pair.remote_cand_id)

      Logger.debug("""
      Ignoring conn check response, non-symmetric src and dst addresses. \
      Sent from: #{inspect({cc_local_cand.base.base_address, cc_local_cand.base.base_port})}, \
      to: #{inspect({cc_remote_cand.address, cc_remote_cand.port})} \
      Recv from: #{inspect({src_ip, src_port})}, on: #{inspect({local_cand.base.base_address, local_cand.base.base_port})} \
      Pair failed: #{conn_check_pair.id}\
      """)

      conn_check_pair = %CandidatePair{
        conn_check_pair
        | state: :failed,
          valid?: false,
          non_symmetric_responses_received: conn_check_pair.non_symmetric_responses_received + 1
      }

      put_in(ice_agent.checklist[conn_check_pair.id], conn_check_pair)
    end
  end

  defp handle_conn_check_success_response(ice_agent, conn_check_pair, msg) do
    with :ok <- authenticate_msg(msg, ice_agent.remote_pwd),
         {:ok, xor_addr} <- Message.get_attribute(msg, XORMappedAddress) do
      {local_cand, ice_agent} = get_or_create_local_cand(ice_agent, xor_addr, conn_check_pair)
      remote_cand = Map.fetch!(ice_agent.remote_cands, conn_check_pair.remote_cand_id)

      valid_pair =
        CandidatePair.new(local_cand, remote_cand, ice_agent.role, :succeeded, valid?: true)

      checklist_pair = Checklist.find_pair(ice_agent.checklist, valid_pair)

      {pair_id, ice_agent} =
        add_valid_pair(ice_agent, valid_pair, conn_check_pair, checklist_pair)

      pair = CandidatePair.schedule_keepalive(ice_agent.checklist[pair_id])

      pair = %CandidatePair{
        pair
        | last_seen: now(),
          responses_received: pair.responses_received + 1
      }

      ice_agent = put_in(ice_agent.checklist[pair.id], pair)

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
        Ignoring conn check response, reason: #{reason}. \
        Conn check tid: #{inspect(msg.transaction_id)}, \
        Conn check pair: #{inspect(conn_check_pair.id)}.\
        """)

        conn_check_pair = %CandidatePair{
          conn_check_pair
          | responses_received: conn_check_pair.responses_received + 1
        }

        put_in(ice_agent.checklist[conn_check_pair.id], conn_check_pair)
    end
  end

  defp handle_conn_check_error_response(ice_agent, conn_check_pair, req, resp) do
    # We only authenticate role conflict as it changes our state.
    # We don't add message-integrity to bad request and unauthenticated errors
    # so we also don't expect to receive it.
    # In the worst case scenario, we won't allow for the connection.
    case Message.get_attribute(resp, ErrorCode) do
      {:ok, %ErrorCode{code: 487}} ->
        handle_role_conflict_error_response(ice_agent, conn_check_pair, req, resp)

      other ->
        Logger.debug(
          "Conn check failed due to error response from the peer, error: #{inspect(other)}"
        )

        conn_check_pair = %CandidatePair{
          conn_check_pair
          | state: :failed,
            valid?: false,
            responses_received: conn_check_pair.responses_received + 1
        }

        checklist = Map.put(ice_agent.checklist, conn_check_pair.id, conn_check_pair)
        %__MODULE__{ice_agent | checklist: checklist}
    end
  end

  defp handle_role_conflict_error_response(ice_agent, conn_check_pair, req, resp) do
    case authenticate_msg(resp, ice_agent.remote_pwd) do
      :ok ->
        {:ok, role} = get_role_attribute(req)

        ice_agent =
          case {role, ice_agent.role} do
            {%ICEControlled{}, :controlling} ->
              # seems that we've already switched
              ice_agent

            {%ICEControlling{}, :controlled} ->
              # seems that we've already switched
              ice_agent

            _ ->
              new_role = if ice_agent.role == :controlling, do: :controlled, else: :controlling

              Logger.debug("""
              Conn check failed due to role conflict. Changing our role to: #{new_role}, \
              recomputing pair priorities, regenerating tiebreaker and rescheduling conn check \
              """)

              tiebreaker = generate_tiebreaker()
              checklist = recompute_pair_prios(ice_agent)

              %__MODULE__{
                ice_agent
                | role: new_role,
                  checklist: checklist,
                  tiebreaker: tiebreaker
              }
          end

        conn_check_pair = %CandidatePair{
          conn_check_pair
          | state: :waiting,
            responses_received: conn_check_pair.responses_received + 1
        }

        checklist = Map.replace!(ice_agent.checklist, conn_check_pair.id, conn_check_pair)

        %__MODULE__{ice_agent | checklist: checklist}

      {:error, reason} ->
        Logger.debug(
          "Couldn't authenticate conn check error response, reason: #{reason}. Ignoring."
        )

        ice_agent
    end
  end

  defp handle_stun_gathering_transaction_response(
         ice_agent,
         %Message{type: %Type{class: :success_response}} = msg
       ) do
    {tr, ice_agent} = pop_in(ice_agent.gathering_transactions[msg.transaction_id])

    {:ok, %XORMappedAddress{address: xor_addr, port: xor_port}} =
      Message.get_attribute(msg, XORMappedAddress)

    case find_local_cand(Map.values(ice_agent.local_cands), xor_addr, xor_port) do
      nil ->
        {:ok, {base_addr, base_port}} = ice_agent.transport_module.sockname(tr.socket)

        priority = Candidate.priority!(ice_agent.local_preferences, base_addr, :srflx)

        cand =
          Candidate.Srflx.new(
            address: xor_addr,
            port: xor_port,
            base_address: base_addr,
            base_port: base_port,
            priority: priority,
            transport_module: ice_agent.transport_module,
            socket: tr.socket
          )

        Logger.debug("New srflx candidate: #{inspect(cand)}")
        notify(ice_agent.on_new_candidate, {:new_candidate, Candidate.Srflx.marshal(cand)})
        # don't pair reflexive candidate, it should be pruned anyway - see sec. 6.1.2.4
        put_in(ice_agent.local_cands[cand.base.id], cand)

      cand ->
        Logger.debug("""
        Not adding srflx candidate as we already have a candidate with the same address.
        Candidate: #{inspect(cand)}
        """)

        ice_agent
    end
  end

  defp handle_stun_gathering_transaction_response(
         ice_agent,
         %Message{type: %Type{class: :error_response}} = msg
       ) do
    {_, ice_agent} = pop_in(ice_agent.gathering_transactions[msg.transaction_id])

    error_code =
      case Message.get_attribute(msg, ErrorCode) do
        {:ok, error_code} -> error_code
        _other -> nil
      end

    Logger.debug(
      "Gathering transaction failed, t_id: #{msg.transaction_id}, reason: #{inspect(error_code)}"
    )

    ice_agent
  end

  defp handle_keepalive_response(
         ice_agent,
         local_cand,
         src_ip,
         src_port,
         %Message{type: %Type{class: :success_response}} = msg
       ) do
    {pair_id, ice_agent} = pop_in(ice_agent.keepalives[msg.transaction_id])
    pair = Map.fetch!(ice_agent.checklist, pair_id)

    with true <- symmetric?(ice_agent, local_cand.base.socket, {src_ip, src_port}, pair),
         :ok <- authenticate_msg(msg, ice_agent.remote_pwd) do
      Logger.debug("Received keepalive success response on: #{pair_info(ice_agent, pair)}")

      pair = %CandidatePair{
        pair
        | last_seen: now(),
          responses_received: pair.responses_received + 1
      }

      put_in(ice_agent.checklist[pair.id], pair)
    else
      false ->
        ka_local_cand = Map.fetch!(ice_agent.local_cands, pair.local_cand_id)
        ka_remote_cand = Map.fetch!(ice_agent.remote_cands, pair.remote_cand_id)

        pair = %CandidatePair{
          pair
          | non_symmetric_responses_received: pair.non_symmetric_responses_received + 1
        }

        ice_agent = put_in(ice_agent.checklist[pair.id], pair)

        Logger.debug("""
        Ignoring keepalive success response, non-symmetric src and dst addresses.
        Sent from: #{inspect({ka_local_cand.base.base_address, ka_local_cand.base.base_port})}, \
        to: #{inspect({ka_remote_cand.address, ka_remote_cand.port})}
        Recv from: #{inspect({src_ip, src_port})}, on: #{inspect({local_cand.base.base_address, local_cand.base.base_port})} \
        Not refreshing last_seen time. \
        """)

        ice_agent

      {:error, reason} ->
        Logger.debug("""
        Couldn't authenticate keepalive success response, reason: #{reason}. \
        Not refreshing last_seen time.\
        """)

        pair = %CandidatePair{pair | responses_received: pair.responses_received + 1}
        put_in(ice_agent.checklist[pair.id], pair)
    end
  end

  defp handle_keepalive_response(
         ice_agent,
         local_cand,
         src_ip,
         src_port,
         %Message{type: %Type{class: :error_response}} = msg
       ) do
    {pair_id, ice_agent} = pop_in(ice_agent.keepalives[msg.transaction_id])
    pair = Map.fetch!(ice_agent.checklist, pair_id)
    pair = %CandidatePair{pair | responses_received: pair.responses_received + 1}
    ice_agent = put_in(ice_agent.checklist[pair.id], pair)

    Logger.debug("""
    Received keepalive error response from #{inspect({src_ip, src_port})}, \
    on: #{inspect({local_cand.base.base_address, local_cand.base.base_port})}. \
    pair: #{pair_info(ice_agent, pair)} \
    Not refreshing last_seen time. \
    """)

    ice_agent
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

  defp add_valid_pair(ice_agent, valid_pair, conn_check_pair, nil) do
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
    local_cand = Map.fetch!(ice_agent.local_cands, pair.local_cand_id)
    remote_cand = Map.fetch!(ice_agent.remote_cands, pair.remote_cand_id)

    src_ip = remote_cand.address
    src_port = remote_cand.port

    type = %Type{class: :success_response, method: :binding}

    resp =
      Message.new(req.transaction_id, type, [%XORMappedAddress{address: src_ip, port: src_port}])
      |> Message.with_integrity(ice_agent.local_pwd)
      |> Message.with_fingerprint()
      |> Message.encode()

    case do_send(ice_agent, local_cand, {src_ip, src_port}, resp) do
      {:ok, ice_agent} ->
        pair = %CandidatePair{pair | responses_sent: pair.responses_sent + 1}
        put_in(ice_agent.checklist[pair.id], pair)

      {:error, ice_agent} ->
        pair = Map.fetch!(ice_agent.checklist, pair.id)

        pair = %CandidatePair{
          pair
          | packets_discarded_on_send: pair.packets_discarded_on_send + 1,
            bytes_discarded_on_send: pair.bytes_discarded_on_send + byte_size(resp)
        }

        put_in(ice_agent.checklist[pair.id], pair)
    end
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

  defp symmetric?(ice_agent, socket, response_src, conn_check_pair) do
    local_cand = Map.fetch!(ice_agent.local_cands, conn_check_pair.local_cand_id)
    remote_cand = Map.fetch!(ice_agent.remote_cands, conn_check_pair.remote_cand_id)

    request_dst = {remote_cand.address, remote_cand.port}
    response_src == request_dst and socket == local_cand.base.socket
  end

  defp get_pair_state(local_cand, remote_cand, checklist_foundations) do
    f = {local_cand.base.foundation, remote_cand.foundation}
    if f in checklist_foundations, do: :frozen, else: :waiting
  end

  defp get_or_create_local_cand(ice_agent, xor_addr, conn_check_pair) do
    conn_check_local_cand = Map.fetch!(ice_agent.local_cands, conn_check_pair.local_cand_id)

    local_cand =
      find_local_cand(Map.values(ice_agent.local_cands), xor_addr.address, xor_addr.port)

    cond do
      # When we try to send UDP datagram from bridge interfaces, that can be used to create local candidates,
      # our source IP address is translated from bridge one to our physical network interface card address.

      # This behavior can cause specific scenarios to arise:

      # L - local side
      # R - remote side
      # RC1 - remote candidate

      # 1. L opens socket on interface 1 (I1), port 5000 - first local candidate (LC1)
      # 2. L opens socket on interface 2 (I2), port 5000 - second local candidate (LC2)
      # 3. L sends a connectivity check from LC1 to RC1.
      #    Given LC1 operates via I1, which is a bridge interface, its source address is rewritten to I2.
      #    This also creates a mapping in host's NAT from I1:5000 to I2:5000.
      # 4. R perceives the request from L as originating from I2, port 5000, and responds successfully to I2, port 5000
      # 5. This response arrives to the I1 port 5000 (because of the mapping in host's NAT).
      #    L notices that R recognized its check as one coming from I2, port 5000.

      # At this moment, sending anything from I2:5000 would require OS to create another mapping in its NAT table from I2:5000 to I2:5000.
      # However, because there is already an existing NAT mapping from I1:5000 to I2:5000 this send operation will fail and return an EPERM error.

      # We consistently use the discovered pair socket for sending.
      # Therefore, we cannot use LC2-RC1 as a valid pair discovered through a check on LC1-RC1.
      # Attempting to send anything from LC1-RC1 would actually involve using the LC2 socket.
      # This action is not possible while the mapping from I1:5000 to I2:5000 exists.
      local_cand && local_cand.base.socket == conn_check_local_cand.base.socket ->
        {local_cand, ice_agent}

      local_cand ->
        {conn_check_local_cand, ice_agent}

      true ->
        # prflx candidate sec 7.2.5.3.1
        # TODO calculate correct prio and foundation
        local_cand = conn_check_local_cand

        priority =
          Candidate.priority!(ice_agent.local_preferences, local_cand.base.base_address, :prflx)

        cand =
          Candidate.Prflx.new(
            address: xor_addr.address,
            port: xor_addr.port,
            base_address: local_cand.base.base_address,
            base_port: local_cand.base.base_port,
            priority: priority,
            transport_module: ice_agent.transport_module,
            socket: local_cand.base.socket
          )

        Logger.debug("Adding new local prflx candidate: #{inspect(cand)}")

        ice_agent = %__MODULE__{
          ice_agent
          | local_cands: Map.put(ice_agent.local_cands, cand.base.id, cand)
        }

        {cand, ice_agent}
    end
  end

  defp get_or_create_remote_cand(ice_agent, src_ip, src_port, prio_attr) do
    case find_remote_cand(Map.values(ice_agent.remote_cands), src_ip, src_port) do
      nil ->
        cand =
          ExICE.Candidate.new(:prflx,
            address: src_ip,
            port: src_port,
            priority: prio_attr.priority
          )

        Logger.debug("Adding new remote prflx candidate: #{inspect(cand)}")
        ice_agent = put_in(ice_agent.remote_cands[cand.id], cand)
        {cand, ice_agent}

      %_cand_mod{} = cand ->
        {cand, ice_agent}
    end
  end

  defp close_candidate(ice_agent, %{base: %{closed?: false}} = local_cand) do
    ice_agent
    |> do_close_candidate(local_cand)
    |> update_connection_state()
  end

  defp close_candidate(ice_agent, _local_cand), do: ice_agent

  defp do_close_candidate(ice_agent, %{base: %{closed?: true}}), do: ice_agent

  defp do_close_candidate(ice_agent, local_cand) do
    Logger.debug("Closing candidate: #{local_cand.base.id}")
    ice_agent = put_in(ice_agent.local_cands[local_cand.base.id].base.closed?, true)

    # clear selected pair if needed
    {pair_changes_diff, selected_pair_id} =
      if ice_agent.selected_pair_id != nil do
        selected_pair = Map.fetch!(ice_agent.checklist, ice_agent.selected_pair_id)

        if selected_pair.local_cand_id == local_cand.base.id do
          Logger.debug("Clearing selected pair: #{selected_pair.id}")
          {1, nil}
        else
          {0, ice_agent.selected_pair_id}
        end
      else
        {0, ice_agent.selected_pair_id}
      end

    # clear pair that's during nomination if needed
    nominating? =
      case ice_agent.nominating? do
        {true, pair_id} ->
          pair = Map.fetch!(ice_agent.checklist, pair_id)

          if pair.local_cand_id == local_cand.base.id do
            {false, nil}
          else
            ice_agent.nominating?
          end

        other ->
          other
      end

    {failed_pair_ids, checklist} = Checklist.close_candidate(ice_agent.checklist, local_cand)

    {failed_conn_checks, conn_checks} =
      Map.split_with(ice_agent.conn_checks, fn {_, conn_check} ->
        conn_check.pair_id in failed_pair_ids
      end)

    {failed_keepalives, keepalives} =
      Map.split_with(ice_agent.keepalives, fn {_, pair_id} -> pair_id in failed_pair_ids end)

    if failed_pair_ids != [] do
      Logger.debug("""
      Marking the following pairs as failed as their local candidate has been closed: #{inspect(failed_pair_ids)}\
      """)
    end

    tr_rtx = ice_agent.tr_rtx -- (Map.keys(failed_conn_checks) ++ Map.keys(failed_keepalives))

    %{
      ice_agent
      | selected_pair_id: selected_pair_id,
        selected_candidate_pair_changes:
          ice_agent.selected_candidate_pair_changes + pair_changes_diff,
        conn_checks: conn_checks,
        keepalives: keepalives,
        tr_rtx: tr_rtx,
        checklist: checklist,
        nominating?: nominating?
    }
  end

  defp close_socket(ice_agent, socket) do
    # Use sockname/1 to determine if a socket is still open.
    # Alternatively, we could create a callback for `:inet.info/1`,
    # but it's return type is not standardized - sometimes it's %{states: [:closed]},
    # some other time %{rstates: [:closed], wstates: [:closed]}.
    case ice_agent.transport_module.sockname(socket) do
      {:error, :closed} -> ice_agent
      _ -> do_close_socket(ice_agent, socket)
    end
  end

  defp do_close_socket(ice_agent, socket) do
    Logger.debug("Closing socket: #{inspect(socket)}")

    ice_agent =
      Enum.reduce(ice_agent.local_cands, ice_agent, fn {_local_cand_id, local_cand}, ice_agent ->
        if local_cand.base.socket == socket do
          do_close_candidate(ice_agent, local_cand)
        else
          ice_agent
        end
      end)

    {removed_gathering_transactions, gathering_transactions} =
      Map.split_with(ice_agent.gathering_transactions, fn {_tr_id, tr} ->
        tr.socket == socket
      end)

    tr_rtx = ice_agent.tr_rtx -- Map.keys(removed_gathering_transactions)

    :ok = ice_agent.transport_module.close(socket)
    :ok = flush_socket_msg(socket)

    %{ice_agent | tr_rtx: tr_rtx, gathering_transactions: gathering_transactions}
  end

  defp flush_socket_msg(socket) do
    receive do
      {:udp, ^socket, _src_ip, _src_port, _packet} ->
        flush_socket_msg(socket)
    after
      0 -> :ok
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

  # In aggressive nomination, there is no additional connectivity check.
  # Instead, every connectivity check includes UseCandidate flag.
  defp time_to_nominate?(%__MODULE__{aggressive_nomination: true}), do: false

  defp time_to_nominate?(%__MODULE__{aggressive_nomination: false, state: :connected} = ice_agent) do
    {nominating?, _} = ice_agent.nominating?
    # if we are not during nomination and we know there won't be further candidates,
    # there are no checks waiting or in-progress,
    # and we are the controlling agent, then we can nominate
    nominating? == false and ice_agent.gathering_state == :complete and
      ice_agent.eoc and
      Checklist.finished?(ice_agent.checklist) and
      ice_agent.role == :controlling
  end

  defp time_to_nominate?(_ice_agent), do: false

  defp try_nominate(ice_agent) do
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

  defp do_restart(ice_agent) do
    Enum.each(ice_agent.sockets, fn socket ->
      case ice_agent.transport_module.sockname(socket) do
        {:ok, {ip, port}} ->
          # we could use close_socket function here but because we are
          # clearing the whole state anyway, we can close the socket manually
          Logger.debug("Closing socket: #{inspect(ip)}:#{port}.")
          :ok = ice_agent.transport_module.close(socket)
          :ok = flush_socket_msg(socket)

        {:error, :closed} ->
          # socket already closed
          :ok
      end
    end)

    {ufrag, pwd} = generate_credentials()

    new_ice_state = :checking

    ice_agent =
      if new_ice_state != ice_agent.state do
        change_connection_state(ice_agent, :checking)
      else
        ice_agent
      end

    ice_agent =
      ice_agent
      |> change_gathering_state(:new)
      |> cancel_eoc_timer()
      |> start_eoc_timer()

    pair_changes_diff = if ice_agent.selected_pair_id != nil, do: 1, else: 0

    %__MODULE__{
      ice_agent
      | sockets: [],
        gathering_transactions: %{},
        selected_pair_id: nil,
        selected_candidate_pair_changes:
          ice_agent.selected_candidate_pair_changes + pair_changes_diff,
        conn_checks: %{},
        checklist: %{},
        tr_rtx: [],
        local_cands: %{},
        remote_cands: %{},
        local_ufrag: ufrag,
        local_pwd: pwd,
        remote_ufrag: nil,
        remote_pwd: nil,
        eoc: false,
        nominating?: {false, nil}
    }
    |> update_ta_timer()
  end

  defp get_foundations(ice_agent) do
    for {_id, pair} <- ice_agent.checklist do
      local_cand = Map.fetch!(ice_agent.local_cands, pair.local_cand_id)
      remote_cand = Map.fetch!(ice_agent.remote_cands, pair.remote_cand_id)
      {local_cand.base.foundation, remote_cand.foundation}
    end
  end

  defp recompute_pair_prios(ice_agent) do
    Map.new(ice_agent.checklist, fn {pair_id, pair} ->
      local_cand = Map.fetch!(ice_agent.local_cands, pair.local_cand_id)
      remote_cand = Map.fetch!(ice_agent.remote_cands, pair.remote_cand_id)

      priority =
        CandidatePair.recompute_priority(
          pair,
          local_cand.base.priority,
          remote_cand.priority,
          ice_agent.role
        )

      {pair_id, priority}
    end)
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

  defp find_relay_cand_by_socket(cands, socket) do
    Enum.find(cands, fn cand -> cand.base.type == :relay and cand.base.socket == socket end)
  end

  defp find_relay_cand_by_client(cands, client_ref) do
    Enum.find(cands, fn cand -> cand.base.type == :relay and cand.client.ref == client_ref end)
  end

  defp find_gathering_transaction(gathering_transactions, client_ref) do
    Enum.find(gathering_transactions, fn
      {_tr_id, %{client: %{ref: ^client_ref}}} -> true
      _ -> false
    end)
  end

  defp parse_ice_servers(ice_servers) do
    # Parse and flatten URLs
    ice_servers
    |> Enum.flat_map(fn ice_server ->
      ice_server.urls
      |> List.wrap()
      |> Enum.map(fn url ->
        case ExSTUN.URI.parse(url) do
          {:ok, url} ->
            ice_server
            |> Map.delete(:urls)
            |> Map.put(:url, url)

          :error ->
            Logger.warning("Couldn't parse URL: #{inspect(url)}. Ignoring.")
            nil
        end
      end)
    end)
    |> Enum.reject(&(&1 == nil))
    |> Enum.split_with(fn ice_server -> ice_server.url.scheme in [:stun, :stuns] end)
  end

  defp generate_tiebreaker() do
    <<tiebreaker::64>> = :crypto.strong_rand_bytes(8)
    tiebreaker
  end

  defp generate_credentials() do
    ufrag = :crypto.strong_rand_bytes(3) |> Base.encode64()
    pwd = :crypto.strong_rand_bytes(16) |> Base.encode64()
    {ufrag, pwd}
  end

  defp pair_info(ice_agent, pair) do
    local_cand = Map.fetch!(ice_agent.local_cands, pair.local_cand_id)
    remote_cand = Map.fetch!(ice_agent.remote_cands, pair.remote_cand_id)

    """
    #{pair.id} \
    l: #{:inet.ntoa(local_cand.base.address)}:#{local_cand.base.port} \
    r: #{:inet.ntoa(remote_cand.address)}:#{remote_cand.port} \
    """
  end

  defp authenticate_msg(msg, pwd) do
    with :ok <- Message.authenticate(msg, pwd),
         :ok <- Message.check_fingerprint(msg) do
      :ok
    else
      {:error, _reason} = err -> err
    end
  end

  defp change_gathering_state(ice_agent, new_gathering_state, opts \\ []) do
    Logger.debug("Gatering state change: #{ice_agent.gathering_state} -> #{new_gathering_state}")

    if opts[:notify] != false do
      notify(ice_agent.on_gathering_state_change, {:gathering_state_change, new_gathering_state})
    end

    %__MODULE__{ice_agent | gathering_state: new_gathering_state}
  end

  defp update_gathering_state(%{gathering_state: :complete} = ice_agent), do: ice_agent

  defp update_gathering_state(ice_agent) do
    transaction_in_progress? =
      Enum.any?(ice_agent.gathering_transactions, fn {_id, %{state: t_state}} ->
        t_state in [:waiting, :in_progress]
      end)

    cond do
      ice_agent.gathering_state == :new and transaction_in_progress? ->
        change_gathering_state(ice_agent, :gathering)

      ice_agent.gathering_state == :gathering and not transaction_in_progress? ->
        change_gathering_state(ice_agent, :complete)

      true ->
        ice_agent
    end
  end

  @doc false
  @spec change_connection_state(t(), atom(), Keyword.t()) :: t()
  def change_connection_state(ice_agent, new_state, opts \\ [])

  def change_connection_state(ice_agent, :failed, opts) do
    ice_agent =
      Enum.reduce(ice_agent.sockets, ice_agent, fn socket, ice_agent ->
        close_socket(ice_agent, socket)
      end)

    # The following fields should be empty when this function is invoked.
    # If they are not, log this fact as warning and clear them so we won't mess up when
    # a late response for gathering transaction or conn check arrives.
    if ice_agent.gathering_transactions != %{} do
      Logger.warning(
        "Requested ICE agent to move to the failed state but gathering transactions are not empty. Clearing gathering transactions."
      )
    end

    if ice_agent.conn_checks != %{} do
      Logger.warning(
        "Requested ICE agent to move to the failed state but conn checks are not empty. Clearing conn checks."
      )
    end

    if ice_agent.keepalives != %{} do
      Logger.warning(
        "Requested ICE agent to move to the failed state but keepalives are not empty. Clearing keepalives."
      )
    end

    if ice_agent.tr_rtx != [] do
      # we don't clear tr_rtx on finished transaction, hence debug
      Logger.debug(
        "Requested ICE agent to move to the failed state but tr_rtx are not empty. Clearing tr_rtx."
      )
    end

    pair_changes_diff = if ice_agent.selected_pair_id != nil, do: 1, else: 0

    %{
      ice_agent
      | gathering_transactions: %{},
        selected_pair_id: nil,
        selected_candidate_pair_changes:
          ice_agent.selected_candidate_pair_changes + pair_changes_diff,
        conn_checks: %{},
        keepalives: %{},
        tr_rtx: [],
        nominating?: {false, nil}
    }
    |> disable_timer()
    |> do_change_connection_state(:failed, opts)
  end

  def change_connection_state(ice_agent, :completed, opts) do
    selected_pair = Map.fetch!(ice_agent.checklist, ice_agent.selected_pair_id)
    succeeded_pair = Map.fetch!(ice_agent.checklist, selected_pair.succeeded_pair_id)

    if selected_pair.id != selected_pair.discovered_pair_id do
      raise """
      Selected pair isn't also discovered pair. This should never happen.
      Selected pair: #{inspect(selected_pair)}\
      """
    end

    succ_local_cand = Map.fetch!(ice_agent.local_cands, succeeded_pair.local_cand_id)
    sel_local_cand = Map.fetch!(ice_agent.local_cands, selected_pair.local_cand_id)

    if succ_local_cand.base.socket != sel_local_cand.base.socket do
      raise """
      Selected local candidate's socket is different than succeeded local candidate's socket. \
      This should never happen as we check against symmetric response.\
      """
    end

    ice_agent =
      Enum.reduce(ice_agent.sockets, ice_agent, fn socket, ice_agent ->
        if socket != sel_local_cand.base.socket do
          close_socket(ice_agent, socket)
        else
          ice_agent
        end
      end)

    do_change_connection_state(ice_agent, :completed, opts)
  end

  def change_connection_state(ice_agent, new_conn_state, opts) do
    do_change_connection_state(ice_agent, new_conn_state, opts)
  end

  defp do_change_connection_state(ice_agent, new_conn_state, opts) do
    Logger.debug("Connection state change: #{ice_agent.state} -> #{new_conn_state}")

    if opts[:notify] != false do
      notify(ice_agent.on_connection_state_change, {:connection_state_change, new_conn_state})
    end

    %__MODULE__{ice_agent | state: new_conn_state}
  end

  defp update_connection_state(%__MODULE__{state: :new} = ice_agent) do
    if Checklist.waiting?(ice_agent.checklist) or Checklist.in_progress?(ice_agent.checklist) do
      Logger.debug("""
      There are pairs waiting or in-progress and we are in the new state. \
      Changing state to checking.\
      """)

      change_connection_state(ice_agent, :checking)
    else
      ice_agent
    end
  end

  # credo:disable-for-next-line Credo.Check.Refactor.CyclomaticComplexity
  defp update_connection_state(%__MODULE__{state: :checking} = ice_agent) do
    cond do
      # in aggressive nomination, we might move directly from checking to completed
      ice_agent.selected_pair_id != nil and ice_agent.eoc == true and
        ice_agent.gathering_state == :complete and Checklist.finished?(ice_agent.checklist) ->
        Logger.debug("""
        Found a valid pair, there won't be any further local or remote candidates. \
        Changing connection state to complete.\
        """)

        change_connection_state(ice_agent, :completed)

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

      # Assuming the controlling side uses regular nomination,
      # the controlled side could move to the completed
      # state as soon as it receives nomination request (or after
      # successful triggered check caused by nomination request).
      # However, to be compatible with the older RFC's aggressive
      # nomination, we wait for the end-of-candidates indication
      # and checklist to be finished.
      # This also means, that if the other side never sets eoc,
      # we will never move to the completed state.
      # This seems to be compliant with libwebrtc.
      ice_agent.role == :controlled and ice_agent.eoc == true and
        ice_agent.gathering_state == :complete and
        ice_agent.selected_pair_id != nil and Checklist.finished?(ice_agent.checklist) ->
        Logger.debug("""
        Finished all conn checks, there won't be any further local or remote candidates
        and we have selected pair. Changing connection state to completed.\
        """)

        change_connection_state(ice_agent, :completed)

      ice_agent.role == :controlling and ice_agent.selected_pair_id != nil and
        ice_agent.eoc == true and ice_agent.gathering_state == :complete and
          Checklist.finished?(ice_agent.checklist) ->
        Logger.debug("""
        Finished all conn checks, there won't be any further local or remote candidates
        and we have selected pair. Changing connection state to completed.\
        """)

        change_connection_state(ice_agent, :completed)

      ice_agent.role == :controlling and match?({true, _pair_id}, ice_agent.nominating?) and
          Map.fetch!(ice_agent.checklist, elem(ice_agent.nominating?, 1)).state == :failed ->
        {_, pair_id} = ice_agent.nominating?

        Logger.debug("""
        Pair we tried to nominate failed. Changing connection state to failed. \
        Pair id: #{pair_id}\
        """)

        change_connection_state(ice_agent, :failed)

      Checklist.get_valid_pair(ice_agent.checklist) == nil and
        Enum.all?(Map.values(ice_agent.local_cands), & &1.base.closed?) and
          ice_agent.gathering_state == :complete ->
        Logger.debug("""
        No valid pairs in state connected, no local candidates and gathering state is complete.
        Changing connection state to failed.\
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
    if ice_agent.selected_pair_id == nil do
      Logger.debug("""
      No selected pair in state completed. Looks like we lost the selected pair.
      Changing connection state to failed.\
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

  defp start_pair_timer() do
    Process.send_after(self(), :pair_timeout, div(@pair_timeout, 2))
  end

  defp start_eoc_timer(ice_agent) do
    timer = Process.send_after(self(), :eoc_timeout, @eoc_timeout)
    %{ice_agent | eoc_timer: timer}
  end

  defp cancel_eoc_timer(%{eoc_timer: nil} = ice_agent), do: ice_agent

  defp cancel_eoc_timer(ice_agent) do
    Process.cancel_timer(ice_agent.eoc_timer)

    receive do
      :eoc_timeout -> :ok
    after
      0 -> :ok
    end

    %{ice_agent | eoc_timer: nil}
  end

  defp work_to_do?(ice_agent) when ice_agent.state in [:completed, :failed], do: false

  defp work_to_do?(ice_agent) do
    gath_trans_in_progress? =
      Enum.any?(ice_agent.gathering_transactions, fn {_id, %{state: t_state}} ->
        t_state in [:waiting, :in_progress]
      end)

    (not Checklist.finished?(ice_agent.checklist) and ice_agent.remote_pwd != nil and
       ice_agent.remote_ufrag != nil) or gath_trans_in_progress?
  end

  defp enable_timer(ice_agent) do
    timer = Process.send_after(self(), :ta_timeout, 0)
    %{ice_agent | ta_timer: timer}
  end

  defp disable_timer(%{ta_timer: nil} = ice_agent), do: ice_agent

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
    Logger.debug("Sending keepalive on #{pair_info(ice_agent, pair)}")
    local_cand = Map.fetch!(ice_agent.local_cands, pair.local_cand_id)
    remote_cand = Map.fetch!(ice_agent.remote_cands, pair.remote_cand_id)

    req = binding_request(ice_agent, local_cand, false)
    raw_req = Message.encode(req)

    dst = {remote_cand.address, remote_cand.port}

    case do_send(ice_agent, local_cand, dst, raw_req) do
      {:ok, ice_agent} ->
        pair = %CandidatePair{pair | requests_sent: pair.requests_sent + 1}
        ice_agent = put_in(ice_agent.checklist[pair.id], pair)
        keepalives = Map.put(ice_agent.keepalives, req.transaction_id, pair.id)
        %__MODULE__{ice_agent | keepalives: keepalives}

      {:error, ice_agent} ->
        pair = Map.fetch!(ice_agent.checklist, pair.id)

        pair = %CandidatePair{
          pair
          | packets_discarded_on_send: pair.packets_discarded_on_send + 1,
            bytes_discarded_on_send: pair.bytes_discarded_on_send + byte_size(raw_req)
        }

        put_in(ice_agent.checklist[pair.id], pair)
    end
  end

  defp send_conn_check(ice_agent, pair) do
    local_cand = Map.fetch!(ice_agent.local_cands, pair.local_cand_id)
    remote_cand = Map.fetch!(ice_agent.remote_cands, pair.remote_cand_id)

    # we can nominate only when being the controlling agent
    # the controlled agent uses nominate? flag according to 7.3.1.5
    nominate =
      ice_agent.role == :controlling and (pair.nominate? or ice_agent.aggressive_nomination)

    # set nominate? flag in case we are running aggressive nomination
    # but don't override it if we are controlled agent and it was already set to true
    pair = %CandidatePair{pair | nominate?: pair.nominate? || nominate}
    ice_agent = put_in(ice_agent.checklist[pair.id], pair)

    req = binding_request(ice_agent, local_cand, nominate)

    raw_req = Message.encode(req)

    dst = {remote_cand.address, remote_cand.port}

    case do_send(ice_agent, local_cand, dst, raw_req) do
      {:ok, ice_agent} ->
        Process.send_after(self(), {:tr_rtx_timeout, req.transaction_id}, @tr_rtx_timeout)

        pair = %CandidatePair{pair | state: :in_progress, requests_sent: pair.requests_sent + 1}

        conn_check = %{
          pair_id: pair.id,
          send_time: now(),
          raw_req: raw_req
        }

        conn_checks = Map.put(ice_agent.conn_checks, req.transaction_id, conn_check)
        checklist = Map.put(ice_agent.checklist, pair.id, pair)
        %__MODULE__{ice_agent | conn_checks: conn_checks, checklist: checklist}

      {:error, ice_agent} ->
        pair = Map.fetch!(ice_agent.checklist, pair.id)

        pair = %CandidatePair{
          pair
          | packets_discarded_on_send: pair.packets_discarded_on_send + 1,
            bytes_discarded_on_send: pair.bytes_discarded_on_send + byte_size(raw_req),
            state: :failed,
            valid?: false
        }

        put_in(ice_agent.checklist[pair.id], pair)
    end
  end

  defp binding_request(ice_agent, local_candidate, nominate) do
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
    priority =
      if local_candidate.base.type == :relay do
        {:ok, {sock_addr, _sock_port}} =
          ice_agent.transport_module.sockname(local_candidate.base.socket)

        Candidate.priority!(ice_agent.local_preferences, sock_addr, :prflx)
      else
        Candidate.priority!(
          ice_agent.local_preferences,
          local_candidate.base.base_address,
          :prflx
        )
      end

    attrs = [
      %Username{value: "#{ice_agent.remote_ufrag}:#{ice_agent.local_ufrag}"},
      %Priority{priority: priority},
      role_attr
    ]

    attrs = if nominate, do: attrs ++ [%UseCandidate{}], else: attrs

    Message.new(type, attrs)
    |> Message.with_integrity(ice_agent.remote_pwd)
    |> Message.with_fingerprint()
  end

  defp do_send(ice_agent, %cand_mod{} = local_cand, dst, data, retry \\ true) do
    {dst_ip, dst_port} = dst

    case cand_mod.send_data(local_cand, dst_ip, dst_port, data) do
      {:ok, local_cand} ->
        ice_agent = put_in(ice_agent.local_cands[local_cand.base.id], local_cand)
        {:ok, ice_agent}

      {:error, reason, local_cand} ->
        if retry do
          # Sometimes, when sending the first UDP datagram,
          # we get an eperm error but retrying seems to help ¯\_(ツ)_/¯
          Logger.debug("""
          Couldn't send data to: #{inspect(dst_ip)}:#{dst_port}, reason: #{reason}, cand: #{inspect(local_cand)}. \
          Retyring...\
          """)

          do_send(ice_agent, local_cand, dst, data, false)
        else
          Logger.debug("""
          Couldn't send data to: #{inspect(dst_ip)}:#{dst_port}, reason: #{reason}, cand: #{inspect(local_cand)}. \
          Closing candidate.\
          """)

          ice_agent = put_in(ice_agent.local_cands[local_cand.base.id], local_cand)

          {:error, ice_agent}
        end
    end
  end

  defp notify(nil, _msg), do: :ok
  defp notify(dst, msg), do: send(dst, {:ex_ice, self(), msg})

  defp now(), do: System.monotonic_time(:millisecond)
end
