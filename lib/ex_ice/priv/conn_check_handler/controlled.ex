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
      nil ->
        Logger.debug("Adding new candidate pair: #{inspect(pair)}")
        checklist = Map.put(ice_agent.checklist, pair.id, pair)
        ice_agent = %ICEAgent{ice_agent | checklist: checklist}
        ICEAgent.send_binding_success_response(ice_agent, pair, msg)

      %CandidatePair{} = checklist_pair ->
        checklist_pair = %CandidatePair{checklist_pair | last_seen: pair.last_seen}
        checklist = Map.put(ice_agent.checklist, checklist_pair.id, checklist_pair)
        ice_agent = %ICEAgent{ice_agent | checklist: checklist}
        ICEAgent.send_binding_success_response(ice_agent, checklist_pair, msg)
    end
  end

  @impl true
  def handle_conn_check_request(ice_agent, pair, msg, %UseCandidate{}) do
    # TODO use triggered check queue
    case Checklist.find_pair(ice_agent.checklist, pair) do
      nil ->
        Logger.debug("""
        Adding new candidate pair that will be nominated after \
        successful conn check: #{inspect(pair.id)}\
        """)

        pair = %CandidatePair{pair | nominate?: true}
        checklist = Map.put(ice_agent.checklist, pair.id, pair)

        ice_agent = %ICEAgent{ice_agent | checklist: checklist}
        ICEAgent.send_binding_success_response(ice_agent, pair, msg)

      %CandidatePair{} = checklist_pair ->
        if checklist_pair.state == :succeeded do
          discovered_pair = Map.fetch!(ice_agent.checklist, checklist_pair.discovered_pair_id)
          discovered_pair = %CandidatePair{discovered_pair | last_seen: pair.last_seen}
          ice_agent = put_in(ice_agent.checklist[discovered_pair.id], discovered_pair)

          if ice_agent.selected_pair_id == nil do
            Logger.debug("Nomination request on pair: #{discovered_pair.id}.")
            update_nominated_flag(ice_agent, discovered_pair.id, true)
          else
            ice_agent
          end
          |> ICEAgent.send_binding_success_response(discovered_pair, msg)
        else
          # TODO should we check if this pair is not in failed?
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

          checklist = Map.put(ice_agent.checklist, checklist_pair.id, checklist_pair)
          ice_agent = %ICEAgent{ice_agent | checklist: checklist}
          ICEAgent.send_binding_success_response(ice_agent, checklist_pair, msg)
        end
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
