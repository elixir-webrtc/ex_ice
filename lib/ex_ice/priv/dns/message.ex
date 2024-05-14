defmodule ExICE.Priv.DNS.Message do
  @moduledoc false
  # DNS Message encoder/decoder implementation.
  # See RFC 1035 (DNS) and RFC 6762 (mDNS).
  # The latter, repurposes the top bit of query and rr class.
  # Limitations:
  # * no support for name compression both when decoding and encoding

  @type t() :: %__MODULE__{
          id: non_neg_integer(),
          qr: boolean(),
          opcode: non_neg_integer(),
          aa: boolean(),
          tc: boolean(),
          rd: boolean(),
          ra: boolean(),
          z: non_neg_integer(),
          rcode: non_neg_integer(),
          question: [map()],
          answer: [map()],
          authority: [map()],
          additional: [map()]
        }

  defstruct id: 0,
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            z: 0,
            rcode: 0,
            question: [],
            answer: [],
            authority: [],
            additional: []

  @spec decode(binary()) :: {:ok, t()} | :error
  def decode(data) do
    with {:ok, header, data} <- decode_header(data),
         {:ok, body, <<>>} <- decode_body(data, header) do
      header = Map.drop(header, [:qdcount, :ancount, :nscount, :arcount])
      msg = Map.merge(header, body)
      {:ok, struct!(__MODULE__, msg)}
    else
      _ -> :error
    end
  end

  @spec encode(t()) :: binary()
  def encode(message) do
    header = encode_header(message)
    body = encode_body(message)
    header <> body
  end

  # PRIVATE FUNCTIONS

  defp decode_header(
         <<id::16, qr::1, opcode::4, aa::1, tc::1, rd::1, ra::1, z::3, rcode::4, qdcount::16,
           ancount::16, nscount::16, arcount::16, data::binary>>
       ) do
    header =
      %{
        id: id,
        qr: qr == 1,
        opcode: opcode,
        aa: aa == 1,
        tc: tc == 1,
        rd: rd == 1,
        ra: ra == 1,
        z: z,
        rcode: rcode,
        qdcount: qdcount,
        ancount: ancount,
        nscount: nscount,
        arcount: arcount
      }

    {:ok, header, data}
  end

  defp decode_header(_other), do: :error

  defp decode_body(data, header) do
    with {:ok, question, data} <- decode_query_section(data, header.qdcount),
         {:ok, answer, data} <- decode_rr_section(data, header.ancount),
         {:ok, authority, data} <- decode_rr_section(data, header.nscount),
         {:ok, additional, data} <- decode_rr_section(data, header.arcount) do
      body = %{question: question, answer: answer, authority: authority, additional: additional}
      {:ok, body, data}
    end
  end

  defp decode_query_section(data, qdcount, acc \\ [])

  defp decode_query_section(data, 0, acc), do: {:ok, Enum.reverse(acc), data}

  defp decode_query_section(data, qdcount, acc) do
    with {:ok, qname, data} <- decode_name(data),
         {:ok, qtype, data} <- decode_type(data),
         {:ok, unicast_response, qclass, data} <- decode_class(data) do
      question = %{
        qname: qname,
        qtype: qtype,
        qclass: qclass,
        unicast_response: unicast_response
      }

      decode_query_section(data, qdcount - 1, [question | acc])
    end
  end

  defp decode_rr_section(data, rr_count, acc \\ [])

  defp decode_rr_section(data, 0, acc), do: {:ok, Enum.reverse(acc), data}

  defp decode_rr_section(data, rr_count, acc) do
    with {:ok, name, data} <- decode_name(data),
         {:ok, type, data} <- decode_type(data),
         {:ok, flush_cache, class, data} <- decode_class(data),
         {:ok, ttl, data} <- decode_ttl(data),
         {:ok, rdata, data} <- decode_rdata(data) do
      rr = %{
        name: name,
        type: type,
        flush_cache: flush_cache,
        class: class,
        ttl: ttl,
        rdata: rdata
      }

      decode_rr_section(data, rr_count - 1, [rr | acc])
    end
  end

  defp decode_name(data, acc \\ [])

  defp decode_name(<<0, rest::binary>>, acc) do
    name =
      acc
      |> Enum.reverse()
      |> Enum.join(".")

    {:ok, name, rest}
  end

  # we don't support pointers right now
  defp decode_name(<<0::2, label_len::6, label::binary-size(label_len), labels::binary>>, acc) do
    decode_name(labels, [label | acc])
  end

  defp decode_name(_, _), do: :error

  defp decode_type(<<1::16, data::binary>>), do: {:ok, :a, data}
  defp decode_type(<<2::16, data::binary>>), do: {:ok, :ns, data}
  defp decode_type(<<3::16, data::binary>>), do: {:ok, :md, data}
  defp decode_type(<<4::16, data::binary>>), do: {:ok, :mf, data}
  defp decode_type(<<5::16, data::binary>>), do: {:ok, :cname, data}
  defp decode_type(<<6::16, data::binary>>), do: {:ok, :soa, data}
  defp decode_type(<<7::16, data::binary>>), do: {:ok, :mb, data}
  defp decode_type(<<8::16, data::binary>>), do: {:ok, :mg, data}
  defp decode_type(<<9::16, data::binary>>), do: {:ok, :mr, data}
  defp decode_type(<<10::16, data::binary>>), do: {:ok, :null, data}
  defp decode_type(<<11::16, data::binary>>), do: {:ok, :wks, data}
  defp decode_type(<<12::16, data::binary>>), do: {:ok, :ptr, data}
  defp decode_type(<<13::16, data::binary>>), do: {:ok, :hinfo, data}
  defp decode_type(<<14::16, data::binary>>), do: {:ok, :minfo, data}
  defp decode_type(<<15::16, data::binary>>), do: {:ok, :mx, data}
  defp decode_type(<<16::16, data::binary>>), do: {:ok, :txt, data}
  defp decode_type(<<47::16, data::binary>>), do: {:ok, :nsec, data}
  defp decode_type(<<252::16, data::binary>>), do: {:ok, :afxr, data}
  defp decode_type(<<253::16, data::binary>>), do: {:ok, :mailb, data}
  defp decode_type(<<254::16, data::binary>>), do: {:ok, :maila, data}
  defp decode_type(<<255::16, data::binary>>), do: {:ok, :*, data}
  defp decode_type(_), do: :error

  # In mDNS, the top bit has special meaning.
  # See RFC 6762, sec. 18.12 and 18.13.
  defp decode_class(<<top_bit::1, 1::15, data::binary>>), do: {:ok, top_bit == 1, :in, data}
  defp decode_class(<<top_bit::1, 2::15, data::binary>>), do: {:ok, top_bit == 1, :cs, data}
  defp decode_class(<<top_bit::1, 3::15, data::binary>>), do: {:ok, top_bit == 1, :ch, data}
  defp decode_class(<<top_bit::1, 4::15, data::binary>>), do: {:ok, top_bit == 1, :hs, data}
  defp decode_class(<<top_bit::1, 255::15, data::binary>>), do: {:ok, top_bit == 1, :*, data}
  defp decode_class(_), do: :error

  defp decode_ttl(<<ttl::32, data::binary>>), do: {:ok, ttl, data}
  defp decode_ttl(_), do: :error

  # leave rdata interpretation to the user
  defp decode_rdata(<<rdlen::16, rdata::binary-size(rdlen), data::binary>>),
    do: {:ok, rdata, data}

  defp decode_rdata(_), do: :error

  defp encode_header(msg) do
    qr = to_int(msg.qr)
    aa = to_int(msg.aa)
    tc = to_int(msg.tc)
    rd = to_int(msg.rd)
    ra = to_int(msg.ra)

    qdcount = length(msg.question)
    ancount = length(msg.answer)
    nscount = length(msg.authority)
    arcount = length(msg.additional)

    <<msg.id::16, qr::1, msg.opcode::4, aa::1, tc::1, rd::1, ra::1, msg.z::3, msg.rcode::4,
      qdcount::16, ancount::16, nscount::16, arcount::16>>
  end

  defp encode_body(msg) do
    encode_query_section(msg.question) <>
      encode_rr_section(msg.answer) <>
      encode_rr_section(msg.authority) <>
      encode_rr_section(msg.additional)
  end

  defp encode_query_section(queries, acc \\ <<>>)
  defp encode_query_section([], acc), do: acc

  defp encode_query_section([query | queries], acc) do
    name = encode_name(query.qname)
    type = encode_type(query.qtype)
    class = encode_class(query.qclass, query.unicast_response)

    acc = acc <> <<name::binary, type::binary, class::binary>>
    encode_query_section(queries, acc)
  end

  defp encode_rr_section(rr, acc \\ <<>>)
  defp encode_rr_section([], acc), do: acc

  defp encode_rr_section([rr | rrs], acc) do
    name = encode_name(rr.name)
    type = encode_type(rr.type)
    class = encode_class(rr.class, rr.flush_cache)
    ttl = <<rr.ttl::32>>
    rdlen = <<byte_size(rr.rdata)::16>>

    encoded_rr =
      <<name::binary, type::binary, class::binary, ttl::binary, rdlen::binary, rr.rdata::binary>>

    acc = acc <> encoded_rr
    encode_rr_section(rrs, acc)
  end

  defp encode_name(name) do
    for label <- String.split(name, "."), into: <<>> do
      size = byte_size(label)
      if size > 63, do: raise("Label #{label} too long. Max length: 63.")
      <<size, label::binary>>
    end <> <<0>>
  end

  defp encode_type(:a), do: <<1::16>>

  defp encode_class(class, top_bit_set) when is_boolean(top_bit_set),
    do: encode_class(class, to_int(top_bit_set))

  defp encode_class(:in, top_bit), do: <<top_bit::1, 1::15>>

  defp to_int(true), do: 1
  defp to_int(false), do: 0
end
