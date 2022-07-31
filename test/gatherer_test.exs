defmodule ExIce.GathererTest do
  use ExUnit.Case

  alias ExIce.Gatherer

  test "" do
    Gatherer.gather_host_candidates()
  end
end
