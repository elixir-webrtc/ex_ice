defmodule ExICE.ConnCheckHandler do
  @moduledoc false

  alias ExICE.CandidatePair
  alias ExICE.Attribute.UseCandidate

  @callback handle_conn_check_request(
              ice_agent :: map(),
              pair :: CandidatePair.t(),
              msg :: ExSTUN.Message.t(),
              use_cand_attr :: UseCandidate.t(),
              key :: binary()
            ) :: map()

  @callback handle_conn_check_success_response(
              ice_agent :: map(),
              conn_check_pair :: CandidatePair.t(),
              response :: ExSTUN.Message.t()
            ) :: map()
end
