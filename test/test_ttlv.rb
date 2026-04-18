# frozen_string_literal: true

require "minitest/autorun"
require_relative "../lib/cyphera_kmip"

class TestTtlv < Minitest::Test
  include CypheraKmip

  def test_encode_decode_integer
    encoded = Ttlv.encode_integer(0x42006A, 1)
    decoded = Ttlv.decode(encoded)
    assert_equal 0x42006A, decoded[:tag]
    assert_equal Ttlv::TYPE_INTEGER, decoded[:type]
    assert_equal 1, decoded[:value]
  end

  def test_encode_decode_enumeration
    encoded = Ttlv.encode_enum(0x42005C, 0x0000000A)
    decoded = Ttlv.decode(encoded)
    assert_equal 0x42005C, decoded[:tag]
    assert_equal Ttlv::TYPE_ENUMERATION, decoded[:type]
    assert_equal 0x0000000A, decoded[:value]
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

  def test_encode_decode_boolean
    encoded = Ttlv.encode_boolean(0x420008, true)
    decoded = Ttlv.decode(encoded)
    assert_equal Ttlv::TYPE_BOOLEAN, decoded[:type]
    assert_equal true, decoded[:value]
  end

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

  def test_text_string_padding
    # "hello" = 5 bytes -> padded to 8 bytes -> total TTLV = 16 bytes
    encoded = Ttlv.encode_text_string(0x420055, "hello")
    assert_equal 16, encoded.bytesize # 8 header + 8 padded value
  end

  def test_empty_text_string
    encoded = Ttlv.encode_text_string(0x420055, "")
    decoded = Ttlv.decode(encoded)
    assert_equal "", decoded[:value]
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
  end
end
