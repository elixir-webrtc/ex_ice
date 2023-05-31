defmodule ExICE.Attribute.Priority do
  alias ExSTUN.Message.RawAttribute

  @behaviour ExSTUN.Message.Attribute

  @attr_type 0x0024

  @type t() :: %__MODULE__{priority: integer()}

  @enforce_keys [:priority]
  defstruct @enforce_keys

  @impl true
  def type(), do: @attr_type

  @impl true
  def from_raw(%RawAttribute{value: <<priority::32>>}, _message) do
    {:ok, %__MODULE__{priority: priority}}
  end

  @impl true
  def from_raw(%RawAttribute{}, _message) do
    {:error, :invalid_priority}
  end

  @impl true
  def to_raw(%__MODULE__{priority: priority}, _msg) do
    %RawAttribute{type: @attr_type, value: <<priority::32>>}
  end
end
