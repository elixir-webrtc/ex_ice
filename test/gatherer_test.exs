defmodule ExICE.GathererTest do
  use ExUnit.Case

  alias ExICE.Gatherer

  test "" do
    Gatherer.gather_host_candidates()
  end
end
