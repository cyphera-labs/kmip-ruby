# frozen_string_literal: true

require "minitest/autorun"
require_relative "../lib/cyphera_kmip"

class TestTtlv < Minitest::Test
  include CypheraKmip

  # ---------------------------------------------------------------------------
  # Primitive encode / decode round-trips
  # ---------------------------------------------------------------------------

  def test_encode_decode_integer
    encoded = Ttlv.encode_integer(0x42006A, 1)
    decoded = Ttlv.decode(encoded)
    assert_equal 0x42006A, decoded[:tag]
    assert_equal Ttlv::TYPE_INTEGER, decoded[:type]
    assert_equal 1, decoded[:value]
  end

  def test_encode_decode_negative_integer
    encoded = Ttlv.encode_integer(0x42006A, -42)
    decoded = Ttlv.decode(encoded)
    assert_equal(-42, decoded[:value])
  end

  def test_encode_decode_max_32bit_integer
    encoded = Ttlv.encode_integer(0x42006A, 0x7FFFFFFF)
    decoded = Ttlv.decode(encoded)
    assert_equal 0x7FFFFFFF, decoded[:value]
  end

  def test_encode_decode_min_32bit_integer
    encoded = Ttlv.encode_integer(0x42006A, -0x80000000)
    decoded = Ttlv.decode(encoded)
    assert_equal(-0x80000000, decoded[:value])
  end

  def test_encode_decode_zero_integer
    encoded = Ttlv.encode_integer(0x42006A, 0)
    decoded = Ttlv.decode(encoded)
    assert_equal 0, decoded[:value]
  end

  def test_encode_decode_enumeration
    encoded = Ttlv.encode_enum(0x42005C, 0x0000000A)
    decoded = Ttlv.decode(encoded)
    assert_equal 0x42005C, decoded[:tag]
    assert_equal Ttlv::TYPE_ENUMERATION, decoded[:type]
    assert_equal 0x0000000A, decoded[:value]
  end

  def test_encode_decode_long_integer
    encoded = Ttlv.encode_long_integer(0x42006A, 1234567890123)
    decoded = Ttlv.decode(encoded)
    assert_equal 0x42006A, decoded[:tag]
    assert_equal Ttlv::TYPE_LONG_INTEGER, decoded[:type]
    assert_equal 1234567890123, decoded[:value]
  end

  def test_encode_decode_negative_long_integer
    encoded = Ttlv.encode_long_integer(0x42006A, -9999999999)
    decoded = Ttlv.decode(encoded)
    assert_equal(-9999999999, decoded[:value])
  end

  def test_encode_decode_text_string
    encoded = Ttlv.encode_text_string(0x420055, "my-key")
    decoded = Ttlv.decode(encoded)
    assert_equal 0x420055, decoded[:tag]
    assert_equal Ttlv::TYPE_TEXT_STRING, decoded[:type]
    assert_equal "my-key", decoded[:value]
  end

  def test_encode_decode_byte_string
    key = ["aabbccdd"].pack("H*")
    encoded = Ttlv.encode_byte_string(0x420043, key)
    decoded = Ttlv.decode(encoded)
    assert_equal 0x420043, decoded[:tag]
    assert_equal Ttlv::TYPE_BYTE_STRING, decoded[:type]
    assert_equal key, decoded[:value]
  end

  def test_encode_decode_boolean_true
    encoded = Ttlv.encode_boolean(0x420008, true)
    decoded = Ttlv.decode(encoded)
    assert_equal Ttlv::TYPE_BOOLEAN, decoded[:type]
    assert_equal true, decoded[:value]
  end

  def test_encode_decode_boolean_false
    encoded = Ttlv.encode_boolean(0x420008, false)
    decoded = Ttlv.decode(encoded)
    assert_equal Ttlv::TYPE_BOOLEAN, decoded[:type]
    assert_equal false, decoded[:value]
  end

  def test_encode_decode_date_time
    ts = 1776700800 # 2026-04-18T12:00:00Z approx
    encoded = Ttlv.encode_date_time(0x420008, ts)
    decoded = Ttlv.decode(encoded)
    assert_equal Ttlv::TYPE_DATE_TIME, decoded[:type]
    assert_equal ts, decoded[:value]
  end

  def test_encode_decode_epoch_zero_date_time
    encoded = Ttlv.encode_date_time(0x420008, 0)
    decoded = Ttlv.decode(encoded)
    assert_equal 0, decoded[:value]
  end

  # ---------------------------------------------------------------------------
  # Padding and alignment
  # ---------------------------------------------------------------------------

  def test_integer_total_size
    encoded = Ttlv.encode_integer(0x42006A, 1)
    # 8 header + 8 padded value = 16 bytes
    assert_equal 16, encoded.bytesize
    # Length field should say 4
    assert_equal 4, encoded.byteslice(4, 4).unpack1("N")
  end

  def test_enum_total_size
    encoded = Ttlv.encode_enum(0x42005C, 1)
    assert_equal 16, encoded.bytesize
    assert_equal 4, encoded.byteslice(4, 4).unpack1("N")
  end

  def test_boolean_uses_8_bytes_value
    encoded = Ttlv.encode_boolean(0x420008, true)
    assert_equal 16, encoded.bytesize # 8 header + 8 value
    assert_equal 8, encoded.byteslice(4, 4).unpack1("N")
  end

  def test_long_integer_uses_8_bytes_value
    encoded = Ttlv.encode_long_integer(0x42006A, 42)
    assert_equal 16, encoded.bytesize
    assert_equal 8, encoded.byteslice(4, 4).unpack1("N")
  end

  def test_text_string_padding
    # "hello" = 5 bytes -> padded to 8 bytes -> total TTLV = 16 bytes
    encoded = Ttlv.encode_text_string(0x420055, "hello")
    assert_equal 16, encoded.bytesize # 8 header + 8 padded value
  end

  def test_text_string_exact_8_bytes_no_padding
    encoded = Ttlv.encode_text_string(0x420055, "12345678")
    assert_equal 16, encoded.bytesize # 8 header + 8 value
  end

  def test_text_string_9_bytes_pads_to_16
    encoded = Ttlv.encode_text_string(0x420055, "123456789")
    assert_equal 24, encoded.bytesize # 8 header + 16 padded
  end

  def test_empty_text_string
    encoded = Ttlv.encode_text_string(0x420055, "")
    assert_equal 8, encoded.bytesize # header only
    decoded = Ttlv.decode(encoded)
    assert_equal "", decoded[:value]
  end

  def test_byte_string_exact_alignment_no_padding
    data = "\xAB".b * 16
    encoded = Ttlv.encode_byte_string(0x420043, data)
    assert_equal 24, encoded.bytesize # 8 header + 16 value
  end

  def test_byte_string_1_extra_byte_pads_to_next_8
    data = "\xAB".b * 17
    encoded = Ttlv.encode_byte_string(0x420043, data)
    assert_equal 32, encoded.bytesize # 8 header + 24 padded
  end

  def test_empty_byte_string
    encoded = Ttlv.encode_byte_string(0x420043, "".b)
    assert_equal 8, encoded.bytesize
    decoded = Ttlv.decode(encoded)
    assert_equal 0, decoded[:value].bytesize
  end

  def test_aes256_key_material_round_trip
    key = ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"].pack("H*")
    encoded = Ttlv.encode_byte_string(0x420043, key)
    assert_equal 40, encoded.bytesize # 8 header + 32 value (exact alignment)
    decoded = Ttlv.decode(encoded)
    assert_equal key, decoded[:value]
  end

  # ---------------------------------------------------------------------------
  # Structures and tree navigation
  # ---------------------------------------------------------------------------

  def test_encode_decode_structure
    encoded = Ttlv.encode_structure(0x420069, [
      Ttlv.encode_integer(0x42006A, 1),
      Ttlv.encode_integer(0x42006B, 4),
    ])
    decoded = Ttlv.decode(encoded)
    assert_equal 0x420069, decoded[:tag]
    assert_equal Ttlv::TYPE_STRUCTURE, decoded[:type]
    assert_equal 2, decoded[:value].length
    assert_equal 1, decoded[:value][0][:value]
    assert_equal 4, decoded[:value][1][:value]
  end

  def test_empty_structure
    encoded = Ttlv.encode_structure(0x420069, [])
    decoded = Ttlv.decode(encoded)
    assert_equal Ttlv::TYPE_STRUCTURE, decoded[:type]
    assert_equal 0, decoded[:value].length
  end

  def test_structure_with_mixed_types
    encoded = Ttlv.encode_structure(0x420069, [
      Ttlv.encode_integer(0x42006A, 42),
      Ttlv.encode_text_string(0x420055, "hello"),
      Ttlv.encode_boolean(0x420008, true),
      Ttlv.encode_byte_string(0x420043, ["cafe"].pack("H*")),
      Ttlv.encode_enum(0x42005C, 0x0A),
    ])
    decoded = Ttlv.decode(encoded)
    assert_equal 5, decoded[:value].length
    assert_equal 42, decoded[:value][0][:value]
    assert_equal "hello", decoded[:value][1][:value]
    assert_equal true, decoded[:value][2][:value]
    assert_equal ["cafe"].pack("H*"), decoded[:value][3][:value]
    assert_equal 0x0A, decoded[:value][4][:value]
  end

  def test_find_child
    encoded = Ttlv.encode_structure(0x420069, [
      Ttlv.encode_integer(0x42006A, 1),
      Ttlv.encode_integer(0x42006B, 4),
    ])
    decoded = Ttlv.decode(encoded)
    child = Ttlv.find_child(decoded, 0x42006B)
    refute_nil child
    assert_equal 4, child[:value]
  end

  def test_find_child_returns_nil_for_missing_tag
    encoded = Ttlv.encode_structure(0x420069, [
      Ttlv.encode_integer(0x42006A, 1),
    ])
    decoded = Ttlv.decode(encoded)
    assert_nil Ttlv.find_child(decoded, 0x42FFFF)
  end

  def test_find_child_returns_nil_for_non_structure
    encoded = Ttlv.encode_integer(0x42006A, 1)
    decoded = Ttlv.decode(encoded)
    assert_nil Ttlv.find_child(decoded, 0x42006A)
  end

  def test_find_children_returns_all_matching
    encoded = Ttlv.encode_structure(0x420069, [
      Ttlv.encode_text_string(0x420094, "id-1"),
      Ttlv.encode_text_string(0x420094, "id-2"),
      Ttlv.encode_text_string(0x420094, "id-3"),
      Ttlv.encode_integer(0x42006A, 99),
    ])
    decoded = Ttlv.decode(encoded)
    ids = Ttlv.find_children(decoded, 0x420094)
    assert_equal 3, ids.length
    assert_equal "id-1", ids[0][:value]
    assert_equal "id-2", ids[1][:value]
    assert_equal "id-3", ids[2][:value]
  end

  def test_find_children_returns_empty_for_non_structure
    encoded = Ttlv.encode_integer(0x42006A, 1)
    decoded = Ttlv.decode(encoded)
    assert_equal [], Ttlv.find_children(decoded, 0x42006A)
  end

  def test_nested_structures
    encoded = Ttlv.encode_structure(0x420078, [
      Ttlv.encode_structure(0x420077, [
        Ttlv.encode_structure(0x420069, [
          Ttlv.encode_integer(0x42006A, 1),
          Ttlv.encode_integer(0x42006B, 4),
        ]),
        Ttlv.encode_integer(0x42000D, 1),
      ]),
    ])
    decoded = Ttlv.decode(encoded)
    assert_equal 0x420078, decoded[:tag]
    header = Ttlv.find_child(decoded, 0x420077)
    refute_nil header
    version = Ttlv.find_child(header, 0x420069)
    refute_nil version
    major = Ttlv.find_child(version, 0x42006A)
    assert_equal 1, major[:value]
    minor = Ttlv.find_child(version, 0x42006B)
    assert_equal 4, minor[:value]
  end

  def test_three_levels_deep_structure
    encoded = Ttlv.encode_structure(0x420001, [
      Ttlv.encode_structure(0x420002, [
        Ttlv.encode_structure(0x420003, [
          Ttlv.encode_text_string(0x420055, "deep"),
        ]),
      ]),
    ])
    decoded = Ttlv.decode(encoded)
    lvl1 = Ttlv.find_child(decoded, 0x420002)
    lvl2 = Ttlv.find_child(lvl1, 0x420003)
    leaf = Ttlv.find_child(lvl2, 0x420055)
    assert_equal "deep", leaf[:value]
  end

  # ---------------------------------------------------------------------------
  # Wire format verification
  # ---------------------------------------------------------------------------

  def test_tag_encoded_as_3_bytes_big_endian
    encoded = Ttlv.encode_integer(0x420069, 0)
    assert_equal 0x42, encoded.getbyte(0)
    assert_equal 0x00, encoded.getbyte(1)
    assert_equal 0x69, encoded.getbyte(2)
  end

  def test_type_byte_correct_for_each_type
    assert_equal Ttlv::TYPE_INTEGER,      Ttlv.encode_integer(0x420001, 0).getbyte(3)
    assert_equal Ttlv::TYPE_LONG_INTEGER, Ttlv.encode_long_integer(0x420001, 0).getbyte(3)
    assert_equal Ttlv::TYPE_ENUMERATION,  Ttlv.encode_enum(0x420001, 0).getbyte(3)
    assert_equal Ttlv::TYPE_BOOLEAN,      Ttlv.encode_boolean(0x420001, true).getbyte(3)
    assert_equal Ttlv::TYPE_TEXT_STRING,   Ttlv.encode_text_string(0x420001, "x").getbyte(3)
    assert_equal Ttlv::TYPE_BYTE_STRING,   Ttlv.encode_byte_string(0x420001, "\x01".b).getbyte(3)
    assert_equal Ttlv::TYPE_STRUCTURE,     Ttlv.encode_structure(0x420001, []).getbyte(3)
    assert_equal Ttlv::TYPE_DATE_TIME,     Ttlv.encode_date_time(0x420001, 0).getbyte(3)
  end

  def test_length_field_4_bytes_big_endian_at_offset_4
    encoded = Ttlv.encode_text_string(0x420055, "AB") # 2 bytes
    assert_equal 2, encoded.byteslice(4, 4).unpack1("N")
  end

  def test_padding_bytes_are_zero_filled
    encoded = Ttlv.encode_text_string(0x420055, "AB") # 2 bytes -> padded to 8
    # Bytes at offset 10-15 should be zero padding
    (10...16).each do |i|
      assert_equal 0, encoded.getbyte(i), "padding byte at #{i} should be 0"
    end
  end

  # ---------------------------------------------------------------------------
  # Error handling
  # ---------------------------------------------------------------------------

  def test_decode_raises_on_buffer_too_short
    assert_raises(RuntimeError) { Ttlv.decode("\x00\x00\x00\x00".b) }
  end

  def test_decode_raises_on_empty_buffer
    assert_raises(RuntimeError) { Ttlv.decode("".b) }
  end

  # ---------------------------------------------------------------------------
  # Unicode and special strings
  # ---------------------------------------------------------------------------

  def test_utf8_multi_byte_characters
    encoded = Ttlv.encode_text_string(0x420055, "caf\u00E9")
    decoded = Ttlv.decode(encoded)
    assert_equal "caf\u00E9", decoded[:value]
  end

  def test_emoji_string
    encoded = Ttlv.encode_text_string(0x420055, "key-\u{1F511}")
    decoded = Ttlv.decode(encoded)
    assert_equal "key-\u{1F511}", decoded[:value]
  end

  def test_long_text_string_crossing_multiple_boundaries
    long_str = "a" * 200
    encoded = Ttlv.encode_text_string(0x420055, long_str)
    decoded = Ttlv.decode(encoded)
    assert_equal long_str, decoded[:value]
  end

  # ---------------------------------------------------------------------------
  # Decoded hash keys
  # ---------------------------------------------------------------------------

  def test_decoded_hash_contains_expected_keys
    encoded = Ttlv.encode_integer(0x42006A, 7)
    decoded = Ttlv.decode(encoded)
    assert_includes decoded.keys, :tag
    assert_includes decoded.keys, :type
    assert_includes decoded.keys, :value
    assert_includes decoded.keys, :length
    assert_includes decoded.keys, :total_length
  end

  def test_total_length_matches_encoded_size
    encoded = Ttlv.encode_text_string(0x420055, "hello")
    decoded = Ttlv.decode(encoded)
    assert_equal encoded.bytesize, decoded[:total_length]
  end
end
