defmodule ExICE.ICEAgent do
  @moduledoc """
  ICE Agent.

  Not to be confused with Elixir Agent.
  """
  use GenServer

  require Logger

  alias ExICE.{Candidate, CandidatePair, Gatherer}
  alias ExICE.Attribute.{ICEControlling, ICEControlled}

  alias ExSTUN.Message
  alias ExSTUN.Message.Type
  alias ExSTUN.Message.Attribute.{Username, XORMappedAddress}

  # Ta timeout in ms
  @ta_timeout 50

  @type role() :: :controlling | :controlled

  @type opts() :: [
          stun_servers :: [String.t()]
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

  ### Server

  @impl true
  def init(opts) do
    {:ok, gather_sup} = Task.Supervisor.start_link()

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
      gather_sup: gather_sup,
      role: Keyword.fetch!(opts, :role),
      checklist: [],
      tr_check_q: [],
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
  def handle_cast({:add_remote_candidate, remote_cand}, state) do
    {:ok, remote_cand} = Candidate.unmarshal(remote_cand)
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
  def handle_info({:new_candidate, cand} = msg, state) do
    # TODO remove self()
    send(state.controlling_process, {self(), msg})
    {:noreply, %{state | local_cands: state.local_cands ++ [cand]}}
  end

  @impl true
  def handle_info(:ta_timeout, state) do
    pair_idx =
      state.checklist
      |> Enum.with_index()
      |> Enum.filter(fn {pair, _idx} -> pair.state == :waiting end)
      |> Enum.max_by(fn {pair, _idx} -> pair.priority end, fn -> nil end)

    state =
      case pair_idx do
        {pair, idx} ->
          Logger.debug("Sending conn check on pair: #{inspect(pair)}")

          pair = send_conn_check(pair, state)

          %{state | checklist: List.update_at(state.checklist, idx, fn _ -> pair end)}

        nil ->
          state
      end

    Process.send_after(self(), :ta_timeout, @ta_timeout)
    {:noreply, state}
  end

  @impl true
  def handle_info({:udp, socket, src_ip, src_port, packet}, state) do
    state =
      if ExSTUN.is_stun(packet) do
        case ExSTUN.Message.decode(packet) do
          {:ok, msg} ->
            handle_stun_msg(socket, src_ip, src_port, msg, state)

          {:error, reason} ->
            Logger.warn("Couldn't decode stun message: #{inspect(reason)}")
            state
        end
      else
        Logger.warn("Got non-stun packet: #{inspect(packet)}. Ignoring...")
        state
      end

    {:noreply, state}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.warn("Got unexpected msg: #{inspect(msg)}")
    {:noreply, state}
  end

  defp handle_stun_msg(socket, src_ip, src_port, msg, state) do
    case msg.type do
      %Type{class: :request, method: :binding} ->
        username = state.local_ufrag <> ":" <> state.remote_ufrag
        password = state.local_pwd
        {:ok, key} = Message.authenticate_st(msg, username, password)
        true = Message.check_fingerprint(msg)

        type = %Type{class: :success_response, method: :binding}
        family = ExICE.Utils.family(src_ip)

        resp =
          Message.new(msg.transaction_id, type, [
            %XORMappedAddress{family: family, address: src_ip, port: src_port}
          ])
          |> Message.with_integrity(key)
          |> Message.with_fingerprint()
          |> Message.encode()

        dst = {src_ip, src_port}

        do_send(socket, dst, resp)

        {remote_cand, state} =
          case find_cand(state.remote_cands, src_ip, src_port) do
            nil ->
              # TODO what about priority
              cand = Candidate.new(:prflx, nil, nil, src_ip, src_port, nil)
              Logger.debug("Adding new peer reflexive candidate: #{inspect(cand)}")
              state = %{state | remote_cands: [cand | state.remote_cands]}
              {cand, state}

            %Candidate{} = cand ->
              {cand, state}
          end

        %Candidate{} = local_cand = find_cand(state.local_cands, socket)

        pair = CandidatePair.new(local_cand, remote_cand, state.role, :waiting)

        # TODO use triggered check queue
        case find_pair(state.checklist, pair) do
          nil ->
            Logger.debug("Adding new candidate pair: #{inspect(pair)}")
            %{state | checklist: [pair | state.checklist]}

          %CandidatePair{} ->
            state
        end

      %Type{class: :success_response, method: :binding} ->
        state

      other ->
        Logger.warn("Unknown msg: #{inspect(other)}")
        state
    end
  end

  defp do_gather_candidates(state) do
    {:ok, host_candidates} = Gatherer.gather_host_candidates()
    # TODO should we override?
    state = %{state | local_cands: state.local_cands ++ host_candidates}

    # for stun_server <- state.stun_servers, host_cand <- host_candidates do
    #   Task.Supervisor.start_child(state.gather_sup, ExICE.Gatherer, :gather_srflx_candidate, [
    #     self(),
    #     host_cand,
    #     stun_server
    #   ])
    # end

    for cand <- host_candidates do
      send(state.controlling_process, {self(), {:new_candidate, Candidate.marshal(cand)}})
    end

    state
  end

  defp find_pair(checklist, pair) do
    # TODO which pairs are actually the same?
    Enum.find(checklist, fn p ->
      p.local_cand.base_address == pair.local_cand.base_address and
        p.local_cand.base_port == pair.local_cand.base_port and
        p.local_cand.address == pair.local_cand.address and
        p.local_cand.port == pair.local_cand.port and
        p.remote_cand.address == pair.remote_cand.address and
        p.remote_cand.port == pair.remote_cand.port
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

    req =
      Message.new(type, [
        %Username{value: "#{state.remote_ufrag}:#{state.local_ufrag}"},
        role_attr
      ])
      |> Message.with_integrity(state.remote_pwd)
      |> Message.with_fingerprint()
      |> Message.encode()

    dst = {pair.remote_cand.address, pair.remote_cand.port}

    do_send(pair.local_cand.socket, dst, req)

    %CandidatePair{pair | state: :in_progress}
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
