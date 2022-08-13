defmodule ExIce.URITest do
  use ExUnit.Case, async: true

  alias ExIce.URI

  describe "URI.parse/1" do
    test "parses valid URI correctly" do
      for {uri_string, expected_uri} <- [
            {
              "stun:stun.l.google.com:19302",
              %URI{scheme: :stun, host: "stun.l.google.com", port: 19_302}
            },
            {
              "stuns:stun.l.google.com:19302",
              %URI{scheme: :stuns, host: "stun.l.google.com", port: 19_302}
            },
            {
              "stun:stun.l.google.com",
              %URI{scheme: :stun, host: "stun.l.google.com", port: 3478}
            },
            {
              "stuns:stun.l.google.com",
              %URI{scheme: :stuns, host: "stun.l.google.com", port: 3478}
            }
          ] do
        assert {:ok, expected_uri} == URI.parse(uri_string)
      end
    end

    test "returns an error for invalid URI" do
      for invalid_uri_string <- [
            "",
            "some random string",
            "stun:",
            "stun::",
            "stun::19302",
            "abcd:stun.l.google.com:19302",
            "stun:stun.l.google.com:ab123",
            "stuns:stun.l.google.com:ab123"
          ] do
        assert :error == URI.parse(invalid_uri_string)
      end
    end
  end
end
