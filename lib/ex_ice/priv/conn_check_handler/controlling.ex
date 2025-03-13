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
        pair = %CandidatePair{pair | requests_received: 1}
        checklist = Map.put(ice_agent.checklist, pair.id, pair)
        ice_agent = %ICEAgent{ice_agent | checklist: checklist}
        ICEAgent.send_binding_success_response(ice_agent, pair, msg)

      %CandidatePair{} = checklist_pair ->
        cond do
          ice_agent.state == :failed ->
            r_pair = resolve_pair(ice_agent, checklist_pair)

            r_pair = %CandidatePair{
              r_pair
              | last_seen: pair.last_seen,
                requests_received: r_pair.requests_received + 1
            }

            put_in(ice_agent.checklist[r_pair.id], r_pair)

          checklist_pair.state == :failed and ice_agent.state == :completed ->
            r_pair = resolve_pair(ice_agent, checklist_pair)

            r_pair = %CandidatePair{
              r_pair
              | last_seen: pair.last_seen,
                requests_received: r_pair.requests_received + 1
            }

            put_in(ice_agent.checklist[r_pair.id], r_pair)

          checklist_pair.state == :failed ->
            r_pair = resolve_pair(ice_agent, checklist_pair)

            r_pair = %CandidatePair{
              r_pair
              | state: :waiting,
                last_seen: pair.last_seen,
                requests_received: r_pair.requests_received + 1
            }

            ice_agent = put_in(ice_agent.checklist[r_pair.id], r_pair)
            ICEAgent.send_binding_success_response(ice_agent, r_pair, msg)

          true ->
            r_pair = resolve_pair(ice_agent, checklist_pair)

            r_pair = %CandidatePair{
              r_pair
              | last_seen: pair.last_seen,
                requests_received: r_pair.requests_received + 1
            }

            ice_agent = put_in(ice_agent.checklist[r_pair.id], r_pair)
            ICEAgent.send_binding_success_response(ice_agent, r_pair, msg)
        end
    end
  end

  @impl true
  def update_nominated_flag(ice_agent, _pair_id, false), do: ice_agent

  @impl true
  def update_nominated_flag(
        %ICEAgent{eoc: eoc, aggressive_nomination: aggressive_nomination} = ice_agent,
        pair_id,
        true
      )
      when (aggressive_nomination == false and eoc == true) or aggressive_nomination == true do
    Logger.debug("Nomination succeeded. Selecting pair: #{inspect(pair_id)}")

    pair = Map.fetch!(ice_agent.checklist, pair_id)
    pair = %CandidatePair{pair | nominate?: false, nominated?: true}
    ice_agent = put_in(ice_agent.checklist[pair.id], pair)

    ice_agent =
      cond do
        ice_agent.selected_pair_id == nil ->
          Logger.debug("Selecting pair: #{pair_id}")
          %ICEAgent{ice_agent | selected_pair_id: pair.id}

        ice_agent.selected_pair_id != nil and pair.id != ice_agent.selected_pair_id ->
          selected_pair = Map.fetch!(ice_agent.checklist, ice_agent.selected_pair_id)

          if pair.priority >= selected_pair.priority do
            Logger.debug("""
            Selecting new pair with higher priority. \
            New pair: #{pair_id}, old pair: #{ice_agent.selected_pair_id}.\
            """)

            %ICEAgent{ice_agent | selected_pair_id: pair.id}
          else
            Logger.debug("Not selecting a new pair as it has lower priority.")
            ice_agent
          end

        true ->
          Logger.debug("Not selecting a new pair as it has the same id")
          ice_agent
      end

    # the controlling agent could nominate only when eoc was set
    # and checklist finished
    if not ice_agent.aggressive_nomination and not Checklist.finished?(ice_agent.checklist) do
      Logger.warning("Nomination succeeded but checklist hasn't finished.")
    end

    %ICEAgent{ice_agent | nominating?: {false, nil}}
  end

  defp resolve_pair(ice_agent, pair) do
    (pair.discovered_pair_id && Map.fetch!(ice_agent.checklist, pair.discovered_pair_id)) || pair
  end
end
