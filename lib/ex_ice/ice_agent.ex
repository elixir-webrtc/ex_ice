defmodule ExICE.ICEAgent do
  @moduledoc """
  ICE Agent.

  Not to be confused with Elixir Agent.
  """
  use GenServer

  require Logger

  alias ExICE.{ICEAgent, Candidate, CandidatePair}

  @typedoc """
  ICE agent role.

  `:controlling` agent is responsible for nominating a pair.
  """
  @type role() :: :controlling | :controlled

  @typedoc """
  Emitted when gathering process state has changed.

  For exact meaning refer to the W3C WebRTC standard, sec 5.6.3.
  """
  @type gathering_state_change() :: {:gathering_state_change, :new | :gathering | :complete}

  @typedoc """
  Emitted when connection state has changed.

  For exact meaning refer to the W3C WebRTC standard, sec. 5.6.4.
  """
  @type connection_state_change() ::
          {:connection_state_change, :checking | :connected | :completed | :failed}

  @typedoc """
  Messages sent by the ExICE.
  """
  @type signal() ::
          {:ex_ice, pid(),
           gathering_state_change()
           | connection_state_change()
           | {:data, binary()}
           | {:new_candidate, binary()}}

  @typedoc """
  ICE Agent configuration options.
  All notifications are by default sent to a process that spawns `ExICE`.
  This behavior can be overwritten using the following options.

  * `ip_filter` - filter applied when gathering local candidates
  * `stun_servers` - list of STUN servers
  * `on_gathering_state_change` - where to send gathering state change notifications. Defaults to a process that spawns `ExICE`.
  * `on_connection_state_change` - where to send connection state change notifications. Defaults to a process that spawns `ExICE`.
  * `on_data` - where to send data. Defaults to a process that spawns `ExICE`.
  * `on_new_candidate` - where to send new candidates. Defaults to a process that spawns `ExICE`.

  Currently, there is no support for local relay (TURN) candidates
  however, remote relay candidates work correctly.
  """
  @type opts() :: [
          ip_filter: (:inet.ip_address() -> boolean),
          stun_servers: [String.t()],
          on_gathering_state_change: pid() | nil,
          on_connection_state_change: pid() | nil,
          on_data: pid() | nil,
          on_new_candidate: pid() | nil
        ]

  @doc """
  Starts and links a new ICE agent.

  Process calling this function is called a `controlling process` and
  has to be prepared for receiving ExICE messages described by `t:signal/0`.
  """
  @spec start_link(role(), opts()) :: GenServer.on_start()
  def start_link(role, opts \\ []) do
    GenServer.start_link(__MODULE__, opts ++ [role: role, controlling_process: self()])
  end

  @doc """
  Configures where to send gathering state change notifications.
  """
  @spec on_gathering_state_change(pid(), pid() | nil) :: :ok
  def on_gathering_state_change(ice_agent, send_to) do
    GenServer.call(ice_agent, {:on_gathering_state_change, send_to})
  end

  @doc """
  Configures where to send connection state change notifications.
  """
  @spec on_connection_state_change(pid(), pid() | nil) :: :ok
  def on_connection_state_change(ice_agent, send_to) do
    GenServer.call(ice_agent, {:on_connection_state_change, send_to})
  end

  @doc """
  Configures where to send data.
  """
  @spec on_data(pid(), pid() | nil) :: :ok
  def on_data(ice_agent, send_to) do
    GenServer.call(ice_agent, {:on_data, send_to})
  end

  @doc """
  Configures where to send new candidates.
  """
  @spec on_new_candidate(pid(), pid() | nil) :: :ok
  def on_new_candidate(ice_agent, send_to) do
    GenServer.call(ice_agent, {:on_new_candidate, send_to})
  end

  @doc """
  Gets local credentials.

  They remain unchanged until ICE restart.
  """
  @spec get_local_credentials(pid()) :: {:ok, ufrag :: binary(), pwd :: binary()}
  def get_local_credentials(ice_agent) do
    GenServer.call(ice_agent, :get_local_credentials)
  end

  @doc """
  Gets local candidates that have been already gathered.
  """
  @spec get_local_candidates(pid()) :: [binary()]
  def get_local_candidates(ice_agent) do
    GenServer.call(ice_agent, :get_local_candidates)
  end

  @doc """
  Gets remote candidates that have been supplied by `add_remote_candidate/2`.
  """
  @spec get_remote_candidates(pid()) :: [binary()]
  def get_remote_candidates(ice_agent) do
    GenServer.call(ice_agent, :get_remote_candidates)
  end

  @doc """
  Sets remote credentials.

  Call to this function is mandatory to start connectivity checks.
  """
  @spec set_remote_credentials(pid(), binary(), binary()) :: :ok
  def set_remote_credentials(ice_agent, ufrag, passwd)
      when is_binary(ufrag) and is_binary(passwd) do
    GenServer.cast(ice_agent, {:set_remote_credentials, ufrag, passwd})
  end

  @doc """
  Starts ICE gathering process.

  Once a new candidate is discovered, it is sent as a message to the controlling process.
  See `t:signal/0` for a message structure.
  """
  @spec gather_candidates(pid()) :: :ok
  def gather_candidates(ice_agent) do
    GenServer.cast(ice_agent, :gather_candidates)
  end

  @doc """
  Adds a remote candidate.

  If an ICE agent has already gathered any local candidates and
  have remote credentials set, adding a remote candidate will start
  connectivity checks.
  """
  @spec add_remote_candidate(pid(), String.t()) :: :ok
  def add_remote_candidate(ice_agent, candidate) when is_binary(candidate) do
    GenServer.cast(ice_agent, {:add_remote_candidate, candidate})
  end

  @doc """
  Informs ICE agent that a remote side finished its gathering process.

  Call to this function is mandatory to nominate a pair (when an agent is the `controlling` one)
  and in turn move to the `completed` state.
  """
  @spec end_of_candidates(pid()) :: :ok
  def end_of_candidates(ice_agent) do
    GenServer.cast(ice_agent, :end_of_candidates)
  end

  @doc """
  Sends data.

  Can only be called after moving to the `connected` state.
  """
  @spec send_data(pid(), binary()) :: :ok
  def send_data(ice_agent, data) when is_binary(data) do
    GenServer.cast(ice_agent, {:send_data, data})
  end

  @doc """
  Gathers ICE agent statistics.

  * `bytes_sent` - data bytes sent. This does not include connectivity checks and UDP/IP header sizes.
  * `bytes_received` - data bytes received. This does not include connectivity checks and UDP/IP header sizes.
  * `packets_sent` - data packets sent. This does not include connectivity checks.
  * `packets_received` - data packets received. This does not include connectivity checks.
  * `candidate_pairs` - list of current candidate pairs. Changes after doing an ICE restart.
  """
  @spec get_stats(pid()) :: %{
          bytes_sent: non_neg_integer(),
          bytes_received: non_neg_integer(),
          packets_sent: non_neg_integer(),
          packets_received: non_neg_integer(),
          state: atom(),
          role: atom(),
          local_ufrag: binary(),
          local_candidates: [Candidate.t()],
          remote_candidates: [Candidate.t()],
          candidate_pairs: [CandidatePair.t()]
        }
  def get_stats(ice_agent) do
    GenServer.call(ice_agent, :get_stats)
  end

  @doc """
  Restarts ICE.

  If there were any valid pairs in the previous ICE session,
  data can still be sent.
  """
  @spec restart(pid()) :: :ok
  def restart(ice_agent) do
    GenServer.cast(ice_agent, :restart)
  end

  @doc """
  Stops ICE agent and all of its sockets.
  """
  @spec stop(pid()) :: :ok
  def stop(ice_agent) do
    GenServer.stop(ice_agent)
  end

  ### Server

  @impl true
  def init(opts) do
    ice_agent = ICEAgent.Impl.new(opts)
    {:ok, %{ice_agent: ice_agent}}
  end

  @impl true
  def handle_call({:on_gathering_state_change, send_to}, _from, state) do
    ice_agent = ICEAgent.Impl.on_gathering_state_change(state.ice_agent, send_to)
    {:reply, :ok, %{state | ice_agent: ice_agent}}
  end

  @impl true
  def handle_call({:on_connection_state_change, send_to}, _from, state) do
    ice_agent = ICEAgent.Impl.on_connection_state_change(state.ice_agent, send_to)
    {:reply, :ok, %{state | ice_agent: ice_agent}}
  end

  @impl true
  def handle_call({:on_data, send_to}, _from, state) do
    ice_agent = ICEAgent.Impl.on_data(state.ice_agent, send_to)
    {:reply, :ok, %{state | ice_agent: ice_agent}}
  end

  @impl true
  def handle_call({:on_new_candidate, send_to}, _from, state) do
    ice_agent = ICEAgent.Impl.on_new_candidate(state.ice_agent, send_to)
    {:reply, :ok, %{state | ice_agent: ice_agent}}
  end

  @impl true
  def handle_call(:get_local_credentials, _from, state) do
    {local_ufrag, local_pwd} = ICEAgent.Impl.get_local_credentials(state.ice_agent)
    {:reply, {:ok, local_ufrag, local_pwd}, state}
  end

  @impl true
  def handle_call(:get_local_candidates, _from, state) do
    candidates = ICEAgent.Impl.get_local_candidates(state.ice_agent)
    {:reply, candidates, state}
  end

  @impl true
  def handle_call(:get_remote_candidates, _from, state) do
    candidates = ICEAgent.Impl.get_remote_candidates(state.ice_agent)
    {:reply, candidates, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = ICEAgent.Impl.get_stats(state.ice_agent)
    {:reply, stats, state}
  end

  @impl true
  def handle_cast({:set_remote_credentials, ufrag, pwd}, state) do
    ice_agent = ICEAgent.Impl.set_remote_credentials(state.ice_agent, ufrag, pwd)
    {:noreply, %{state | ice_agent: ice_agent}}
  end

  @impl true
  def handle_cast(:gather_candidates, state) do
    ice_agent = ICEAgent.Impl.gather_candidates(state.ice_agent)
    {:noreply, %{state | ice_agent: ice_agent}}
  end

  @impl true
  def handle_cast({:add_remote_candidate, remote_cand}, state) do
    ice_agent = ICEAgent.Impl.add_remote_candidate(state.ice_agent, remote_cand)
    {:noreply, %{state | ice_agent: ice_agent}}
  end

  @impl true
  def handle_cast(:end_of_candidates, state) do
    ice_agent = ICEAgent.Impl.end_of_candidates(state.ice_agent)
    {:noreply, %{state | ice_agent: ice_agent}}
  end

  @impl true
  def handle_cast({:send_data, data}, state) do
    ice_agent = ICEAgent.Impl.send_data(state.ice_agent, data)
    {:noreply, %{state | ice_agent: ice_agent}}
  end

  @impl true
  def handle_cast(:restart, state) do
    ice_agent = ICEAgent.Impl.restart(state.ice_agent)
    {:noreply, %{state | ice_agent: ice_agent}}
  end

  @impl true
  def handle_info(:ta_timeout, state) do
    ice_agent = ICEAgent.Impl.handle_timeout(state.ice_agent)
    {:noreply, %{state | ice_agent: ice_agent}}
  end

  @impl true
  def handle_info({:keepalive, id}, state) do
    ice_agent = ICEAgent.Impl.handle_keepalive(state.ice_agent, id)
    {:noreply, %{state | ice_agent: ice_agent}}
  end

  @impl true
  def handle_info({:udp, socket, src_ip, src_port, packet}, state) do
    ice_agent = ICEAgent.Impl.handle_udp(state.ice_agent, socket, src_ip, src_port, packet)
    {:noreply, %{state | ice_agent: ice_agent}}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.warning("Got unexpected msg: #{inspect(msg)}")
    {:noreply, state}
  end

  @impl true
  def terminate(reason, _state) do
    # we don't need to close sockets manually as this is done automatically by Erlang
    Logger.debug("Stopping ICE agent with reason: #{inspect(reason)}")
  end
end
