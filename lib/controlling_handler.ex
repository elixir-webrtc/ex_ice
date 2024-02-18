defmodule ExICE.ControllingHandler do
  @moduledoc false
  @behaviour ExICE.ConnCheckHandler

  require Logger

  alias ExICE.{CandidatePair, Checklist, ICEAgentPriv}
  alias ExICE.Attribute.UseCandidate

  @impl true
  def handle_conn_check_request(state, pair, msg, %UseCandidate{}, _key) do
    Logger.debug("""
    Received conn check request with use candidate attribute but
    we are the controlling side. Sending 400 bad request error response.
    Pair: #{pair.id}.
    """)

    ICEAgentPriv.send_bad_request_error_response(pair, msg)
    state
  end

  @impl true
  def handle_conn_check_request(state, pair, msg, nil, key) do
    ICEAgentPriv.send_binding_success_response(pair, msg, key)

    # TODO use triggered check queue
    case Checklist.find_pair(state.checklist, pair) do
      nil ->
        Logger.debug("Adding new candidate pair: #{inspect(pair)}")
        checklist = Map.put(state.checklist, pair.id, pair)
        %ICEAgentPriv{state | checklist: checklist}

      %CandidatePair{} = pair
      when state.selected_pair != nil and pair.discovered_pair_id == state.selected_pair.id ->
        # to be honest this might also be a retransmission
        Logger.debug("Keepalive on selected pair: #{pair.discovered_pair_id}")
        state

      %CandidatePair{} ->
        # keepalive/retransmission?
        state
    end
  end

  @impl true
  def update_nominated_flag(state, _pair_id, false), do: state

  @impl true
  def update_nominated_flag(%{eoc: true} = state, pair_id, true) do
    Logger.debug("Nomination succeeded. Selecting pair: #{inspect(pair_id)}")
    state = ICEAgentPriv.change_connection_state(:completed, state)

    pair = Map.fetch!(state.checklist, pair_id)
    pair = %CandidatePair{pair | nominate?: false, nominated?: true}
    checklist = Map.put(state.checklist, pair.id, pair)
    state = %ICEAgentPriv{state | checklist: checklist}

    # the controlling agent could nominate only when eoc was set
    # and checklist finished
    unless Checklist.finished?(state.checklist) do
      Logger.warning("Nomination succeeded but checklist hasn't finished.")
    end

    %{state | nominating?: {false, nil}, selected_pair: pair}
  end
end
