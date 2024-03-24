defmodule ExICE.Priv.Attribute.ICEControlling do
  @moduledoc false

  alias ExSTUN.Message.RawAttribute

  @behaviour ExSTUN.Message.Attribute

  @attr_type 0x802A

  @type t() :: %__MODULE__{tiebreaker: integer()}

  @enforce_keys [:tiebreaker]
  defstruct @enforce_keys

  @impl true
  def type(), do: @attr_type

  @impl true
  def from_raw(%RawAttribute{value: <<tiebreaker::64>>}, _message) do
    {:ok, %__MODULE__{tiebreaker: tiebreaker}}
  end

  @impl true
  def from_raw(%RawAttribute{}, _message) do
    {:error, :invalid_ice_controlling}
  end

  @impl true
  def to_raw(%__MODULE__{tiebreaker: tiebreaker}, _msg) do
    %RawAttribute{type: @attr_type, value: <<tiebreaker::64>>}
  end
end
