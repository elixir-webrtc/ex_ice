defmodule SignallingServer.PeerHandler do
  alias SignallingServer.Room

  require Logger

  def init(options) do
    Room.join()
    {:ok, options}
  end

  def handle_in({msg, [opcode: :text]}, state) do
    # forward msg to the other peer
    Room.forward(msg)
    {:ok, state}
  end

  def handle_info({:forward, msg}, state) do
    # send msg from the other peer
    {:reply, :ok, {:text, msg}, state}
  end

  def handle_info(msg, state) do
    Logger.warn("Unknown msg: #{inspect(msg)}")
    {:ok, state}
  end

  def terminate(:timeout, state) do
    {:ok, state}
  end
end
