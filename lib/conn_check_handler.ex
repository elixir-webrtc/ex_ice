defmodule ExICE.ConnCheckHandler do
  @moduledoc false

  alias ExICE.CandidatePair
  alias ExICE.Attribute.UseCandidate

  @callback handle_conn_check_request(
              ice_agent :: map(),
              pair :: CandidatePair.t(),
              request :: ExSTUN.Message.t(),
              use_cand_attr :: UseCandidate.t(),
              key :: binary()
            ) :: map()

  @callback update_nominated_flag(
              ice_agent :: map(),
              pair_id :: term(),
              nominate? :: boolean()
            ) :: map()
end
