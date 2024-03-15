# credo:disable-for-this-file Credo.Check.Refactor.CyclomaticComplexity
defmodule ExICE.ConnCheckHandler.Controlled do
  @moduledoc false
  @behaviour ExICE.ConnCheckHandler

  require Logger

  alias ExICE.{CandidatePair, Checklist, ICEAgent}
  alias ExICE.Attribute.UseCandidate

  @impl true
  def handle_conn_check_request(ice_agent, pair, msg, nil) do
    ICEAgent.Impl.send_binding_success_response(
      ice_agent.transport_module,
      pair,
      msg,
      ice_agent.local_pwd
    )

    # TODO use triggered check queue
    case Checklist.find_pair(ice_agent.checklist, pair) do
      nil ->
        Logger.debug("Adding new candidate pair: #{inspect(pair)}")
        checklist = Map.put(ice_agent.checklist, pair.id, pair)
        %ICEAgent.Impl{ice_agent | checklist: checklist}

      %CandidatePair{} = pair
      when ice_agent.selected_pair != nil and
             pair.discovered_pair_id == ice_agent.selected_pair.id ->
        # to be honest this might also be a retransmission
        Logger.debug("Keepalive on selected pair: #{pair.discovered_pair_id}")
        ice_agent

      %CandidatePair{} ->
        # keepalive/retransmission?
        ice_agent
    end
  end

  @impl true
  def handle_conn_check_request(ice_agent, pair, msg, %UseCandidate{}) do
    ICEAgent.Impl.send_binding_success_response(
      ice_agent.transport_module,
      pair,
      msg,
      ice_agent.local_pwd
    )

    # TODO use triggered check queue
    case Checklist.find_pair(ice_agent.checklist, pair) do
      nil ->
        Logger.debug("""
        Adding new candidate pair that will be nominated after \
        successfull conn check: #{inspect(pair.id)}\
        """)

        pair = %CandidatePair{pair | nominate?: true}
        checklist = Map.put(ice_agent.checklist, pair.id, pair)
        %ICEAgent.Impl{ice_agent | checklist: checklist}

      %CandidatePair{} = pair
      when ice_agent.selected_pair != nil and
             pair.discovered_pair_id == ice_agent.selected_pair.id ->
        Logger.debug("Keepalive on selected pair: #{pair.id}")
        ice_agent

      %CandidatePair{} = pair ->
        if pair.state == :succeeded do
          Logger.debug("Nomination request on pair: #{pair.id}.")
          update_nominated_flag(ice_agent, pair.discovered_pair_id, true)
        else
          # TODO should we check if this pair is not in failed?
          Logger.debug("""
          Nomination request on pair that hasn't been verified yet.
          We will nominate pair once conn check passes.
          Pair: #{inspect(pair.id)}
          """)

          pair = %CandidatePair{pair | nominate?: true}
          checklist = Map.put(ice_agent.checklist, pair.id, pair)
          %ICEAgent.Impl{ice_agent | checklist: checklist}
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
    ice_agent = %ICEAgent.Impl{ice_agent | checklist: checklist}

    cond do
      ice_agent.selected_pair == nil ->
        Logger.debug("Selecting pair: #{pair_id}")
        %ICEAgent.Impl{ice_agent | selected_pair: pair}

      ice_agent.selected_pair != nil and pair.priority >= ice_agent.selected_pair.priority ->
        Logger.debug("""
        Selecting new pair with higher priority. \
        New pair: #{pair_id}, old pair: #{ice_agent.selected_pair.id}.\
        """)

        %ICEAgent.Impl{ice_agent | selected_pair: pair}

      true ->
        Logger.debug("Not selecting a new pair as it has lower priority")
        ice_agent
    end
  end
end
