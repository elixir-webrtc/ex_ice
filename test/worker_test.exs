defmodule ExICE.WorkerTest do
  use ExUnit.Case, async: true

  alias ExICE.Worker

  describe "Worker.gather_candidates/0" do
    @tag :debug
    test "" do
      stun_servers = ["stun:stun.l.google.com:19302"]
      {:ok, worker} = Worker.start_link(stun_servers: stun_servers)
      Worker.gather_candidates(worker)

      Process.sleep(1000)
    end
  end
end
