# credo:disable-for-this-file Credo.Check.Refactor.CyclomaticComplexity
defmodule ExICE.ControlledHandler do
  @moduledoc false
  @behaviour ExICE.ConnCheckHandler

  require Logger

  alias ExICE.{CandidatePair, Checklist, ICEAgent}
  alias ExICE.Attribute.UseCandidate

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
  def handle_conn_check_request(state, pair, msg, %UseCandidate{}, key) do
    ICEAgent.send_binding_success_response(pair, msg, key)

    # TODO use triggered check queue
    case Checklist.find_pair(state.checklist, pair) do
      nil ->
        Logger.debug("""
        Adding new candidate pair that will be nominated after \
        successfull conn check: #{inspect(pair.id)}\
        """)

        pair = %CandidatePair{pair | nominate?: true}
        put_in(state, [:checklist, pair.id], pair)

      %CandidatePair{} = pair when pair == state.selected_pair ->
        Logger.debug("Keepalive on selected pair: #{pair.id}")
        state

      %CandidatePair{} = pair ->
        if pair.state == :succeeded do
          # FIXME we should check against valid? flag
          # it's possible to have to pairs: one with state succeeded
          # and flag valid? set to false, and the other one with state
          # succeeded and flag valid? set to true
          # TODO should we call this selected or nominated pair
          Logger.debug("Nomination request on valid pair: #{pair.id}.")
          update_nominated_flag(state, pair.id, true)
        else
          # TODO should we check if this pair is not in failed?
          Logger.debug("""
          Nomination request on pair that hasn't been verified yet.
          We will nominate pair once conn check passes.
          Pair: #{inspect(pair.id)}
          """)

          pair = %CandidatePair{pair | nominate?: true}
          put_in(state, [:checklist, pair.id], pair)
        end
    end
  end

  @impl true
  def update_nominated_flag(state, _pair_id, false), do: state

  @impl true
  def update_nominated_flag(state, pair_id, true) do
    Logger.debug("Nomination succeeded, pair: #{pair_id}")

    pair = Map.fetch!(state.checklist, pair_id)

    state =
      cond do
        state.selected_pair == nil ->
          Logger.debug("Selecting pair: #{pair_id}")
          %{state | selected_pair: pair}

        state.selected_pair != nil and pair.priority >= state.selected_pair.priority ->
          Logger.debug("""
          Selecting new pair with higher priority. \
          New pair: #{pair_id}, old pair: #{state.selected_pair.id}.\
          """)

          %{state | selected_pair: pair}

        true ->
          Logger.debug("Not selecting a new pair as it has lower priority")
          state
      end

    checklist =
      Map.update!(state.checklist, pair_id, fn pair ->
        %CandidatePair{pair | nominate?: false, nominated?: true}
      end)

    %{state | checklist: checklist, selected_pair: Map.fetch!(checklist, pair_id)}
  end
end
