defmodule ExICE.Priv.ConnCheckHandler.Controlling do
  @moduledoc false
  @behaviour ExICE.Priv.ConnCheckHandler

  require Logger

  alias ExICE.Priv.{CandidatePair, Checklist, ICEAgent}
  alias ExICE.Priv.Attribute.UseCandidate

  @impl true
  def handle_conn_check_request(ice_agent, pair, msg, %UseCandidate{}) do
    Logger.debug("""
    Received conn check request with use candidate attribute but
    we are the controlling side. Sending 400 bad request error response.
    Pair: #{pair.id}.
    """)

    local_cand = Map.fetch!(ice_agent.local_cands, pair.local_cand_id)
    remote_cand = Map.fetch!(ice_agent.remote_cands, pair.remote_cand_id)

    dst = {remote_cand.address, remote_cand.port}

    ICEAgent.send_bad_request_error_response(ice_agent, local_cand, dst, msg)
  end

  @impl true
  def handle_conn_check_request(ice_agent, pair, msg, nil) do
    # TODO use triggered check queue
    case Checklist.find_pair(ice_agent.checklist, pair) do
      nil when ice_agent.state in [:completed, :failed] ->
        Logger.warning("""
        Received conn check request for non-existing pair in unexpected state: #{ice_agent.state}. Ignoring\
        """)

        ice_agent

      nil when ice_agent.state in [:new, :checking, :connected] ->
        Logger.debug("Adding new candidate pair: #{inspect(pair)}")
        checklist = Map.put(ice_agent.checklist, pair.id, pair)
        ice_agent = %ICEAgent{ice_agent | checklist: checklist}
        ICEAgent.send_binding_success_response(ice_agent, pair, msg)

      %CandidatePair{} = checklist_pair ->
        cond do
          checklist_pair.state == :failed and ice_agent.state in [:failed, :completed] ->
            # update last seen so we can observe that something is received but don't reply
            # as we are in the failed state
            checklist_pair = %CandidatePair{checklist_pair | last_seen: pair.last_seen}
            put_in(ice_agent.checklist[checklist_pair.id], checklist_pair)

          checklist_pair.state == :failed ->
            checklist_pair = %CandidatePair{
              checklist_pair
              | state: :waiting,
                last_seen: pair.last_seen
            }

            ice_agent = put_in(ice_agent.checklist[checklist_pair.id], checklist_pair)
            ICEAgent.send_binding_success_response(ice_agent, checklist_pair, msg)

          true ->
            checklist_pair = %CandidatePair{checklist_pair | last_seen: pair.last_seen}
            ice_agent = put_in(ice_agent.checklist[checklist_pair.id], checklist_pair)
            ICEAgent.send_binding_success_response(ice_agent, checklist_pair, msg)
        end
    end
  end

  @impl true
  def update_nominated_flag(ice_agent, _pair_id, false), do: ice_agent

  @impl true
  def update_nominated_flag(%ICEAgent{eoc: true} = ice_agent, pair_id, true) do
    Logger.debug("Nomination succeeded. Selecting pair: #{inspect(pair_id)}")

    pair = Map.fetch!(ice_agent.checklist, pair_id)
    pair = %CandidatePair{pair | nominate?: false, nominated?: true}
    ice_agent = put_in(ice_agent.checklist[pair.id], pair)

    # the controlling agent could nominate only when eoc was set
    # and checklist finished
    unless Checklist.finished?(ice_agent.checklist) do
      Logger.warning("Nomination succeeded but checklist hasn't finished.")
    end

    ice_agent = %ICEAgent{ice_agent | nominating?: {false, nil}, selected_pair_id: pair.id}
    ICEAgent.change_connection_state(ice_agent, :completed)
  end
end
