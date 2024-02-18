defmodule ExICE.ConnCheckHandler do
  @moduledoc false

  alias ExICE.{CandidatePair, ICEAgentPriv}
  alias ExICE.Attribute.UseCandidate

  @doc """
  Called when conn check request arrives.
  """
  @callback handle_conn_check_request(
              ice_agent :: ICEAgentPriv.t(),
              pair :: CandidatePair.t(),
              request :: ExSTUN.Message.t(),
              use_cand_attr :: UseCandidate.t(),
              key :: binary()
            ) :: ICEAgentPriv.t()

  @doc """
  Called after processing conn check success response.

  Its implementation is based on sec. 7.2.5.3.4.

  `pair_id` is the id of valid pair, not the succeeded one.

  The meaning of `nominate?` flag depends on the ice agent role.

  In case of controlled, it means that either we received nomination
  request on pair, or we received conn check success response for the
  request that was triggered by the other side's conn check request
  with use_candidate flag.

  In case of controlling side, it simply means we received conn check
  success response for our nomination request.
  """
  @callback update_nominated_flag(
              ice_agent :: ICEAgentPriv.t(),
              pair_id :: term(),
              nominate? :: boolean()
            ) :: ICEAgentPriv.t()
end
