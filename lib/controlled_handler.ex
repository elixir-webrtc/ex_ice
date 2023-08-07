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
          # TODO should we call this selected or nominated pair
          Logger.debug("Nomination request on valid pair. Selecting pair: #{inspect(pair.id)}")

          pair = %CandidatePair{pair | nominated?: true}

          if state.state != :completed do
            send(state.controlling_process, {:ex_ice, self(), :completed})
          end

          state = %{state | selected_pair: pair, state: :completed}
          put_in(state, [:checklist, pair.id], pair)
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
    Logger.debug("Nomination succeeded. Selecting pair: #{inspect(pair_id)}")
    # send(state.controlling_process, {:ex_ice, self(), :completed})
    checklist =
      Map.update!(state.checklist, pair_id, fn pair ->
        %CandidatePair{pair | nominate?: false, nominated?: true}
      end)

    # %{state | checklist: checklist, state: :completed, selected_pair: Map.fetch!(state.checklist, pair_id)}
    # TODO selected_pair?
    %{state | checklist: checklist, selected_pair: Map.fetch!(state.checklist, pair_id)}
  end
end
