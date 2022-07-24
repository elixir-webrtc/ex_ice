defmodule ExIce.GathererTest do
  use ExUnit.Case

  alias ExIce.Gatherer

  test "" do
    Gatherer.gather_host_candidates(self())

    receive do
      x -> IO.inspect(x, label: :x)
    after
      2000 ->
        :ok
    end
  end
end
