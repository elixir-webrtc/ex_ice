defmodule ExICE.ControllingHandler do
  @moduledoc false
  @behaviour ExICE.ConnCheckHandler

  require Logger

  alias ExICE.{CandidatePair, Checklist, ICEAgent}
  alias ExICE.Attribute.UseCandidate

  alias ExSTUN.Message
  alias ExSTUN.Message.Attribute.XORMappedAddress

  defguard are_pairs_equal(p1, p2)
           when p1.local_cand.base_address == p2.local_cand.base_address and
                  p1.local_cand.base_port == p2.local_cand.base_port and
                  p1.local_cand.address == p2.local_cand.address and
                  p1.local_cand.port == p2.local_cand.port and
                  p1.remote_cand.address == p2.remote_cand.address and
                  p1.remote_cand.port == p2.remote_cand.port

  @impl true
  def handle_conn_check_request(state, pair, msg, %UseCandidate{}, _key) do
    Logger.debug("""
    Received conn check request with use candidate attribute but
    we are the controlling side. Sending 400 bad request error response.
    Pair: #{pair.id}. 
    """)

    ICEAgent.send_bad_request_error_response(pair, msg)
    state
  end

  @impl true
  def handle_conn_check_request(state, pair, msg, nil, key) do
    ICEAgent.send_binding_success_response(pair, msg, key)

    # TODO use triggered check queue
    case Checklist.find_pair(state.checklist, pair) do
      nil ->
        Logger.debug("Adding new candidate pair: #{inspect(pair)}")
        put_in(state, [:checklist, pair.id], pair)

      %CandidatePair{} = pair when pair == state.selected_pair ->
        # to be honest this might also be a retransmission
        Logger.debug("Keepalive on selected pair: #{pair.id}")
        state

      %CandidatePair{} ->
        # keepalive/retransmission?
        state
    end
  end

  @impl true
  def handle_conn_check_success_response(state, conn_check_pair, msg) do
    case Message.get_attribute(msg, XORMappedAddress) do
      {:ok, xor_addr} ->
        {local_cand, state} = ICEAgent.get_or_create_local_cand(xor_addr, conn_check_pair, state)
        remote_cand = conn_check_pair.remote_cand

        valid_pair =
          CandidatePair.new(local_cand, remote_cand, state.role, :succeeded, valid?: true)

        case Checklist.find_pair(state.checklist, valid_pair) do
          %CandidatePair{valid?: true} = pair ->
            # valid pair is already in the checklist
            # and that wasn't first conn check on it -
            # the pair is marked as valid so we had to
            # nominate it
            true = pair.nominate?

            pair = %CandidatePair{
              pair
              | state: :succeeded,
                nominate?: false,
                nominated?: true
            }

            Logger.debug("Nomination succeeded. Selecting pair: #{inspect(pair.id)}")
            send(state.controlling_process, {:ex_ice, self(), :completed})
            checklist = Map.replace!(state.checklist, pair.id, pair)
            %{state | checklist: checklist, state: :completed, selected_pair: pair}

          checklist_pair ->
            # there is no such pair in the checklist
            # or it is the first conn check on that pair
            add_valid_pair(valid_pair, conn_check_pair, checklist_pair, state)
        end

      _other ->
        Logger.debug("""
        Invalid or no XORMappedAddress. Ignoring conn check response.
        Conn check tid: #{inspect(msg.transaction_id)},
        Conn check pair: #{inspect(conn_check_pair.id)}.
        """)

        state
    end
  end

  # Adds valid pair according to sec 7.2.5.3.2
  # TODO sec. 7.2.5.3.3
  # The agent MUST set the states for all other Frozen candidate pairs in
  # all checklists with the same foundation to Waiting.
  defp add_valid_pair(valid_pair, conn_check_pair, _, state)
       when are_pairs_equal(valid_pair, conn_check_pair) do
    Logger.debug("""
    New valid pair: #{inspect(conn_check_pair.id)} \
    resulted from conn check on pair: #{inspect(conn_check_pair.id)}\
    """)

    conn_check_pair = %CandidatePair{conn_check_pair | state: :succeeded, valid?: true}

    if state.state not in [:connected, :completed] do
      send(state.controlling_process, {:ex_ice, self(), :connected})
    end

    checklist = Map.replace!(state.checklist, conn_check_pair.id, conn_check_pair)

    %{state | state: :connected, checklist: checklist}
  end

  defp add_valid_pair(valid_pair, conn_check_pair, checklist_pair, state)
       when are_pairs_equal(valid_pair, checklist_pair) do
    Logger.debug("""
    New valid pair: #{inspect(checklist_pair.id)} \
    resulted from conn check on pair: #{inspect(conn_check_pair.id)}\
    """)

    conn_check_pair = %CandidatePair{conn_check_pair | state: :succeeded}
    checklist_pair = %CandidatePair{checklist_pair | state: :succeeded, valid?: true}

    if state.state not in [:connected, :completed] do
      send(state.controlling_process, {:ex_ice, self(), :connected})
    end

    checklist =
      state.checklist
      |> Map.replace!(conn_check_pair.id, conn_check_pair)
      |> Map.replace!(checklist_pair.id, checklist_pair)

    %{state | state: :connected, checklist: checklist}
  end

  defp add_valid_pair(valid_pair, conn_check_pair, _, state) do
    # TODO compute priority according to sec 7.2.5.3.2
    Logger.debug("""
    Adding new candidate pair resulted from conn check \
    on pair: #{inspect(conn_check_pair.id)}. Pair: #{inspect(valid_pair)}\
    """)

    Logger.debug("New valid pair: #{inspect(valid_pair.id)}")

    conn_check_pair = %CandidatePair{conn_check_pair | state: :succeeded}

    if state.state not in [:connected, :completed] do
      send(state.controlling_process, {:ex_ice, self(), :connected})
    end

    checklist =
      state.checklist
      |> Map.replace!(conn_check_pair.id, conn_check_pair)
      |> Map.put(valid_pair.id, valid_pair)

    %{state | state: :connected, checklist: checklist}
  end
end
