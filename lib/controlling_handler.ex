defmodule ExICE.ControllingHandler do
  @moduledoc false
  @behaviour ExICE.ConnCheckHandler

  require Logger

  alias ExICE.{CandidatePair, Checklist, ICEAgentPriv}
  alias ExICE.Attribute.UseCandidate

  @impl true
  def handle_conn_check_request(ice_agent, pair, msg, %UseCandidate{}, _key) do
    Logger.debug("""
    Received conn check request with use candidate attribute but
    we are the controlling side. Sending 400 bad request error response.
    Pair: #{pair.id}.
    """)

    ICEAgentPriv.send_bad_request_error_response(pair, msg)
    ice_agent
  end

  @impl true
  def handle_conn_check_request(ice_agent, pair, msg, nil, key) do
    ICEAgentPriv.send_binding_success_response(pair, msg, key)

    # TODO use triggered check queue
    case Checklist.find_pair(ice_agent.checklist, pair) do
      nil ->
        Logger.debug("Adding new candidate pair: #{inspect(pair)}")
        checklist = Map.put(ice_agent.checklist, pair.id, pair)
        %ICEAgentPriv{ice_agent | checklist: checklist}

      %CandidatePair{} = pair
      when ice_agent.selected_pair != nil and pair.discovered_pair_id == ice_agent.selected_pair.id ->
        # to be honest this might also be a retransmission
        Logger.debug("Keepalive on selected pair: #{pair.discovered_pair_id}")
        ice_agent

      %CandidatePair{} ->
        # keepalive/retransmission?
        ice_agent
    end
  end

  @impl true
  def update_nominated_flag(ice_agent, _pair_id, false), do: ice_agent

  @impl true
  def update_nominated_flag(%ICEAgentPriv{eoc: true} = ice_agent, pair_id, true) do
    Logger.debug("Nomination succeeded. Selecting pair: #{inspect(pair_id)}")
    ice_agent = ICEAgentPriv.change_connection_state(:completed, ice_agent)

    pair = Map.fetch!(ice_agent.checklist, pair_id)
    pair = %CandidatePair{pair | nominate?: false, nominated?: true}
    checklist = Map.put(ice_agent.checklist, pair.id, pair)
    ice_agent = %ICEAgentPriv{ice_agent | checklist: checklist}

    # the controlling agent could nominate only when eoc was set
    # and checklist finished
    unless Checklist.finished?(ice_agent.checklist) do
      Logger.warning("Nomination succeeded but checklist hasn't finished.")
    end

    %ICEAgentPriv{ice_agent | nominating?: {false, nil}, selected_pair: pair}
  end
end
