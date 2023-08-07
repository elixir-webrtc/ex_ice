defmodule ExICE.ControllingHandler do
  @moduledoc false
  @behaviour ExICE.ConnCheckHandler

  require Logger

  alias ExICE.{CandidatePair, Checklist, ICEAgent}
  alias ExICE.Attribute.UseCandidate

  @impl true
  def handle_conn_check_request(state, pair, msg, %UseCandidate{}, _key) do
    Logger.debug("""
    Received conn check request with use candidate attribute but
    we are the controlling side. Sending 400 bad request error response.
    Pair: #{pair.id}. 
    """)

    ICEAgent.send_bad_request_error_response(pair, msg)
    state
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
  def update_nominated_flag(state, _pair_id, false), do: state

  @impl true
  def update_nominated_flag(state, pair_id, true) do
    Logger.debug("Nomination succeeded. Selecting pair: #{inspect(pair_id)}")
    send(state.controlling_process, {:ex_ice, self(), :completed})

    checklist =
      Map.update!(state.checklist, pair_id, fn pair ->
        %CandidatePair{pair | nominate?: false, nominated?: true}
      end)

    %{
      state
      | checklist: checklist,
        state: :completed,
        selected_pair: Map.fetch!(state.checklist, pair_id)
    }
  end
end
