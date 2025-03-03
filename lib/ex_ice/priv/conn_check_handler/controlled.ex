# credo:disable-for-this-file Credo.Check.Refactor.CyclomaticComplexity
defmodule ExICE.Priv.ConnCheckHandler.Controlled do
  @moduledoc false
  @behaviour ExICE.Priv.ConnCheckHandler

  require Logger

  alias ExICE.Priv.{CandidatePair, Checklist, ICEAgent}
  alias ExICE.Priv.Attribute.UseCandidate

  @impl true
  def handle_conn_check_request(ice_agent, pair, msg, nil) do
    # TODO use triggered check queue
    case Checklist.find_pair(ice_agent.checklist, pair) do
      nil when ice_agent.state in [:completed, :failed] ->
        # This is to make sure we won't add a new pair with prflx candidate
        # after we have moved to the completed or failed state.
        # Alternatively, we could answer with error message.
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
  def handle_conn_check_request(ice_agent, pair, msg, %UseCandidate{}) do
    # TODO use triggered check queue
    case Checklist.find_pair(ice_agent.checklist, pair) do
      nil when ice_agent.state in [:completed, :failed] ->
        Logger.warning("""
        Received conn check request for non-existing pair in unexpected state: #{ice_agent.state}. Ignoring\
        """)

        ice_agent

      nil when ice_agent.state in [:new, :checking, :connected] ->
        Logger.debug("""
        Adding new candidate pair that will be nominated after \
        successful conn check: #{inspect(pair.id)}\
        """)

        pair = %CandidatePair{pair | nominate?: true}
        checklist = Map.put(ice_agent.checklist, pair.id, pair)

        ice_agent = %ICEAgent{ice_agent | checklist: checklist}
        ICEAgent.send_binding_success_response(ice_agent, pair, msg)

      %CandidatePair{state: :succeeded} = checklist_pair when ice_agent.state != :failed ->
        discovered_pair = Map.fetch!(ice_agent.checklist, checklist_pair.discovered_pair_id)
        discovered_pair = %CandidatePair{discovered_pair | last_seen: pair.last_seen}
        ice_agent = put_in(ice_agent.checklist[discovered_pair.id], discovered_pair)

        if ice_agent.selected_pair_id != discovered_pair.id do
          Logger.debug("Nomination request on pair: #{discovered_pair.id}.")
          update_nominated_flag(ice_agent, discovered_pair.id, true)
        else
          ice_agent
        end
        |> ICEAgent.send_binding_success_response(discovered_pair, msg)

      %CandidatePair{state: :failed} = checklist_pair
      when ice_agent.state not in [:completed, :failed] ->
        Logger.debug("""
        Nomination request on failed pair. Re-scheduling pair for conn-check.
        We will nominate pair once conn check passes.
        Pair: #{inspect(checklist_pair.id)}
        """)

        checklist_pair = %CandidatePair{
          checklist_pair
          | nominate?: true,
            last_seen: pair.last_seen,
            state: :waiting
        }

        ice_agent = put_in(ice_agent.checklist[checklist_pair.id], checklist_pair)
        ICEAgent.send_binding_success_response(ice_agent, checklist_pair, msg)

      %CandidatePair{} = checklist_pair when ice_agent.state not in [:completed, :failed] ->
        Logger.debug("""
        Nomination request on pair that hasn't been verified yet.
        We will nominate pair once conn check passes.
        Pair: #{inspect(checklist_pair.id)}
        """)

        checklist_pair = %CandidatePair{
          checklist_pair
          | nominate?: true,
            last_seen: pair.last_seen
        }

        ice_agent = put_in(ice_agent.checklist[checklist_pair.id], checklist_pair)
        ICEAgent.send_binding_success_response(ice_agent, checklist_pair, msg)

      %CandidatePair{} = checklist_pair ->
        checklist_pair = %CandidatePair{checklist_pair | last_seen: pair.last_seen}
        put_in(ice_agent.checklist[checklist_pair.id], checklist_pair)
    end
  end

  @impl true
  def update_nominated_flag(ice_agent, _pair_id, false), do: ice_agent

  @impl true
  def update_nominated_flag(ice_agent, pair_id, true) do
    Logger.debug("Nomination succeeded, pair: #{pair_id}")

    pair = Map.fetch!(ice_agent.checklist, pair_id)
    pair = %CandidatePair{pair | nominate?: false, nominated?: true}

    checklist = Map.put(ice_agent.checklist, pair.id, pair)
    ice_agent = %ICEAgent{ice_agent | checklist: checklist}

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
          ice_agent
        end

      true ->
        Logger.debug("Not selecting a new pair as it has lower priority or has the same id")
        ice_agent
    end
  end
end
