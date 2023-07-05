defmodule ExICE.Attribute.ICEControlling do
  @moduledoc false

  alias ExSTUN.Message.RawAttribute

  @behaviour ExSTUN.Message.Attribute

  @attr_type 0x802A

  @type t() :: %__MODULE__{tie_breaker: integer()}

  @enforce_keys [:tie_breaker]
  defstruct @enforce_keys

  @impl true
  def type(), do: @attr_type

  @impl true
  def from_raw(%RawAttribute{value: <<tie_breaker::64>>}, _message) do
    {:ok, %__MODULE__{tie_breaker: tie_breaker}}
  end

  @impl true
  def from_raw(%RawAttribute{}, _message) do
    {:error, :invalid_ice_controlling}
  end

  @impl true
  def to_raw(%__MODULE__{tie_breaker: tie_breaker}, _msg) do
    %RawAttribute{type: @attr_type, value: <<tie_breaker::64>>}
  end
end
