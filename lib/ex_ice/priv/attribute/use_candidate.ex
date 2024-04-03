defmodule ExICE.Priv.Attribute.UseCandidate do
  @moduledoc false

  alias ExSTUN.Message.RawAttribute

  @behaviour ExSTUN.Message.Attribute

  @attr_type 0x0025

  @type t() :: %__MODULE__{}

  @enforce_keys []
  defstruct @enforce_keys

  @impl true
  def type(), do: @attr_type

  @impl true
  def from_raw(%RawAttribute{value: <<>>}, _message) do
    {:ok, %__MODULE__{}}
  end

  @impl true
  def from_raw(%RawAttribute{}, _message) do
    {:error, :invalid_use_candidate}
  end

  @impl true
  def to_raw(%__MODULE__{}, _msg) do
    %RawAttribute{type: @attr_type, value: <<>>}
  end
end
