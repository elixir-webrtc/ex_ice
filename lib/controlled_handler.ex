# credo:disable-for-this-file Credo.Check.Refactor.CyclomaticComplexity
defmodule ExICE.ControlledHandler do
  @moduledoc false
  @behaviour ExICE.ConnCheckHandler

  require Logger

  alias ExICE.{CandidatePair, Checklist, ICEAgent}
  alias ExICE.Attribute.UseCandidate

  @impl true
  def handle_checklist(state) do
    case Checklist.get_next_pair(state.checklist) do
      %CandidatePair{} = pair ->
        Logger.debug("Sending conn check on pair: #{inspect(pair.id)}")
        {pair, state} = ICEAgent.send_conn_check(pair, state)
        put_in(state, [:checklist, pair.id], pair)

      nil ->
        cond do
          # if we knew, the other side uses regular nomination
          # we would move to the completed state as soon as we 
          # received nomination request but because we don't
          # know wheter the other side uses regular or aggressive
          # nomination we have to be prepared for the case
          # where there is selected pair and we are not in the completed 
          Checklist.finished?(state.checklist) and state.gathering_state == :complete and
            state.selected_pair != nil and state.eoc == true ->
            Logger.debug("""
            Finished all conn checks, there won't be any further local or remote candidates
            and we have selected pair. Changing connection state to completed.
            """)

            ICEAgent.change_connection_state(:completed, state)

          # if we know, there are won't be any remote (eoc==true) and 
          # local (gathering_state==complete) candidates, we finished 
          # performing all conn checks and there is no selected or valid pair
          # (state.state==checking), move to the failed state
          Checklist.finished?(state.checklist) and state.gathering_state == :complete and
            state.eoc == true and state.state == :checking ->
            Logger.debug("""
            Finished all conn checks, there won't be any further local or remote candidates
            and we don't have any valid or selected pair. Changing connection state to failed.
            """)

            ICEAgent.change_connection_state(:failed, state)

          true ->
            state
        end
    end
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

    checklist_finished? =
      not (Checklist.in_progress?(state.checklist) or Checklist.waiting?(state.checklist))

    state =
      if state.eoc and checklist_finished? and state.gathering_state == :complete and
           state.state != :completed do
        # Assuming the controlling side uses regulard nomination, 
        # the controlled side could move to the completed
        # state as soon as it receives nomination request (or after 
        # successful triggered check caused by nomination request).
        # However, to be compatible with the older RFC's aggresive
        # nomination, we wait for the end-of-candidates indication
        # and checklist to be finished.
        # This also means, that if the other side never sets eoc,
        # we will never move to the completed state.
        # This seems to be compliant with libwebrtc.
        ICEAgent.change_connection_state(:completed, state)
      else
        state
      end

    checklist =
      Map.update!(state.checklist, pair_id, fn pair ->
        %CandidatePair{pair | nominate?: false, nominated?: true}
      end)

    %{state | checklist: checklist, selected_pair: Map.fetch!(checklist, pair_id)}
  end
end
