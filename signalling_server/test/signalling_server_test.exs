defmodule SignallingServerTest do
  use ExUnit.Case
  doctest SignallingServer

  test "greets the world" do
    assert SignallingServer.hello() == :world
  end
end
