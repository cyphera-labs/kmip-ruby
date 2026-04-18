# frozen_string_literal: true

require "minitest/autorun"
require_relative "../lib/cyphera_kmip"

class TestOperations < Minitest::Test
  include CypheraKmip

  # ---------------------------------------------------------------------------
  # Request building
  # ---------------------------------------------------------------------------

  def test_build_locate_request_produces_valid_ttlv
    request = Operations.build_locate_request("test-key")
    decoded = Ttlv.decode(request)
    assert_equal Tag::REQUEST_MESSAGE, decoded[:tag]
    assert_equal Ttlv::TYPE_STRUCTURE, decoded[:type]
  end

  def test_build_locate_request_contains_protocol_version_1_4
    decoded = Ttlv.decode(Operations.build_locate_request("k"))
    header = Ttlv.find_child(decoded, Tag::REQUEST_HEADER)
    refute_nil header
    version = Ttlv.find_child(header, Tag::PROTOCOL_VERSION)
    refute_nil version
    major = Ttlv.find_child(version, Tag::PROTOCOL_VERSION_MAJOR)
    minor = Ttlv.find_child(version, Tag::PROTOCOL_VERSION_MINOR)
    assert_equal Operations::PROTOCOL_MAJOR, major[:value]
    assert_equal Operations::PROTOCOL_MINOR, minor[:value]
  end

  def test_build_locate_request_has_batch_count_1
    decoded = Ttlv.decode(Operations.build_locate_request("k"))
    header = Ttlv.find_child(decoded, Tag::REQUEST_HEADER)
    count = Ttlv.find_child(header, Tag::BATCH_COUNT)
    assert_equal 1, count[:value]
  end

  def test_build_locate_request_has_locate_operation
    decoded = Ttlv.decode(Operations.build_locate_request("k"))
    batch = Ttlv.find_child(decoded, Tag::BATCH_ITEM)
    op = Ttlv.find_child(batch, Tag::OPERATION)
    assert_equal Operation::LOCATE, op[:value]
  end

  def test_build_locate_request_contains_name_attribute
    decoded = Ttlv.decode(Operations.build_locate_request("my-key"))
    batch = Ttlv.find_child(decoded, Tag::BATCH_ITEM)
    payload = Ttlv.find_child(batch, Tag::REQUEST_PAYLOAD)
    attr = Ttlv.find_child(payload, Tag::ATTRIBUTE)
    attr_name = Ttlv.find_child(attr, Tag::ATTRIBUTE_NAME)
    assert_equal "Name", attr_name[:value]
    attr_value = Ttlv.find_child(attr, Tag::ATTRIBUTE_VALUE)
    name_value = Ttlv.find_child(attr_value, Tag::NAME_VALUE)
    assert_equal "my-key", name_value[:value]
  end

  def test_build_get_request_produces_valid_ttlv
    request = Operations.build_get_request("unique-id-123")
    decoded = Ttlv.decode(request)
    assert_equal Tag::REQUEST_MESSAGE, decoded[:tag]
  end

  def test_build_get_request_has_get_operation
    decoded = Ttlv.decode(Operations.build_get_request("uid"))
    batch = Ttlv.find_child(decoded, Tag::BATCH_ITEM)
    op = Ttlv.find_child(batch, Tag::OPERATION)
    assert_equal Operation::GET, op[:value]
  end

  def test_build_get_request_contains_unique_identifier
    decoded = Ttlv.decode(Operations.build_get_request("uid-456"))
    batch = Ttlv.find_child(decoded, Tag::BATCH_ITEM)
    payload = Ttlv.find_child(batch, Tag::REQUEST_PAYLOAD)
    uid = Ttlv.find_child(payload, Tag::UNIQUE_IDENTIFIER)
    assert_equal "uid-456", uid[:value]
  end

  def test_build_create_request_produces_valid_ttlv
    request = Operations.build_create_request("new-key")
    decoded = Ttlv.decode(request)
    assert_equal Tag::REQUEST_MESSAGE, decoded[:tag]
  end

  def test_build_create_request_has_create_operation
    decoded = Ttlv.decode(Operations.build_create_request("k"))
    batch = Ttlv.find_child(decoded, Tag::BATCH_ITEM)
    op = Ttlv.find_child(batch, Tag::OPERATION)
    assert_equal Operation::CREATE, op[:value]
  end

  def test_build_create_request_uses_symmetric_key_object_type
    decoded = Ttlv.decode(Operations.build_create_request("k"))
    batch = Ttlv.find_child(decoded, Tag::BATCH_ITEM)
    payload = Ttlv.find_child(batch, Tag::REQUEST_PAYLOAD)
    obj_type = Ttlv.find_child(payload, Tag::OBJECT_TYPE)
    assert_equal ObjectType::SYMMETRIC_KEY, obj_type[:value]
  end

  def test_build_create_request_defaults_to_aes
    decoded = Ttlv.decode(Operations.build_create_request("k"))
    batch = Ttlv.find_child(decoded, Tag::BATCH_ITEM)
    payload = Ttlv.find_child(batch, Tag::REQUEST_PAYLOAD)
    tmpl = Ttlv.find_child(payload, Tag::TEMPLATE_ATTRIBUTE)
    attrs = Ttlv.find_children(tmpl, Tag::ATTRIBUTE)
    algo_attr = attrs.find do |a|
      name = Ttlv.find_child(a, Tag::ATTRIBUTE_NAME)
      name && name[:value] == "Cryptographic Algorithm"
    end
    refute_nil algo_attr
    algo_value = Ttlv.find_child(algo_attr, Tag::ATTRIBUTE_VALUE)
    assert_equal Algorithm::AES, algo_value[:value]
  end

  def test_build_create_request_defaults_to_256_bit_length
    decoded = Ttlv.decode(Operations.build_create_request("k"))
    batch = Ttlv.find_child(decoded, Tag::BATCH_ITEM)
    payload = Ttlv.find_child(batch, Tag::REQUEST_PAYLOAD)
    tmpl = Ttlv.find_child(payload, Tag::TEMPLATE_ATTRIBUTE)
    attrs = Ttlv.find_children(tmpl, Tag::ATTRIBUTE)
    len_attr = attrs.find do |a|
      name = Ttlv.find_child(a, Tag::ATTRIBUTE_NAME)
      name && name[:value] == "Cryptographic Length"
    end
    refute_nil len_attr
    len_value = Ttlv.find_child(len_attr, Tag::ATTRIBUTE_VALUE)
    assert_equal 256, len_value[:value]
  end

  def test_build_create_request_includes_encrypt_decrypt_usage_mask
    decoded = Ttlv.decode(Operations.build_create_request("k"))
    batch = Ttlv.find_child(decoded, Tag::BATCH_ITEM)
    payload = Ttlv.find_child(batch, Tag::REQUEST_PAYLOAD)
    tmpl = Ttlv.find_child(payload, Tag::TEMPLATE_ATTRIBUTE)
    attrs = Ttlv.find_children(tmpl, Tag::ATTRIBUTE)
    usage_attr = attrs.find do |a|
      name = Ttlv.find_child(a, Tag::ATTRIBUTE_NAME)
      name && name[:value] == "Cryptographic Usage Mask"
    end
    refute_nil usage_attr
    usage_value = Ttlv.find_child(usage_attr, Tag::ATTRIBUTE_VALUE)
    assert_equal(UsageMask::ENCRYPT | UsageMask::DECRYPT, usage_value[:value])
  end

  def test_build_create_request_includes_key_name
    decoded = Ttlv.decode(Operations.build_create_request("prod-key"))
    batch = Ttlv.find_child(decoded, Tag::BATCH_ITEM)
    payload = Ttlv.find_child(batch, Tag::REQUEST_PAYLOAD)
    tmpl = Ttlv.find_child(payload, Tag::TEMPLATE_ATTRIBUTE)
    attrs = Ttlv.find_children(tmpl, Tag::ATTRIBUTE)
    name_attr = attrs.find do |a|
      name = Ttlv.find_child(a, Tag::ATTRIBUTE_NAME)
      name && name[:value] == "Name"
    end
    refute_nil name_attr
    name_struct = Ttlv.find_child(name_attr, Tag::ATTRIBUTE_VALUE)
    name_value = Ttlv.find_child(name_struct, Tag::NAME_VALUE)
    assert_equal "prod-key", name_value[:value]
  end

  def test_build_create_request_custom_algorithm_and_length
    decoded = Ttlv.decode(Operations.build_create_request("k", Algorithm::TRIPLE_DES, 192))
    batch = Ttlv.find_child(decoded, Tag::BATCH_ITEM)
    payload = Ttlv.find_child(batch, Tag::REQUEST_PAYLOAD)
    tmpl = Ttlv.find_child(payload, Tag::TEMPLATE_ATTRIBUTE)
    attrs = Ttlv.find_children(tmpl, Tag::ATTRIBUTE)

    algo_attr = attrs.find do |a|
      name = Ttlv.find_child(a, Tag::ATTRIBUTE_NAME)
      name && name[:value] == "Cryptographic Algorithm"
    end
    algo_value = Ttlv.find_child(algo_attr, Tag::ATTRIBUTE_VALUE)
    assert_equal Algorithm::TRIPLE_DES, algo_value[:value]

    len_attr = attrs.find do |a|
      name = Ttlv.find_child(a, Tag::ATTRIBUTE_NAME)
      name && name[:value] == "Cryptographic Length"
    end
    len_value = Ttlv.find_child(len_attr, Tag::ATTRIBUTE_VALUE)
    assert_equal 192, len_value[:value]
  end

  # ---------------------------------------------------------------------------
  # Response parsing
  # ---------------------------------------------------------------------------

  def build_mock_response(operation, status, payload_children = [])
    batch_children = [
      Ttlv.encode_enum(Tag::OPERATION, operation),
      Ttlv.encode_enum(Tag::RESULT_STATUS, status),
    ]
    unless payload_children.empty?
      batch_children << Ttlv.encode_structure(Tag::RESPONSE_PAYLOAD, payload_children)
    end
    Ttlv.encode_structure(Tag::RESPONSE_MESSAGE, [
      Ttlv.encode_structure(Tag::RESPONSE_HEADER, [
        Ttlv.encode_structure(Tag::PROTOCOL_VERSION, [
          Ttlv.encode_integer(Tag::PROTOCOL_VERSION_MAJOR, 1),
          Ttlv.encode_integer(Tag::PROTOCOL_VERSION_MINOR, 4),
        ]),
        Ttlv.encode_integer(Tag::BATCH_COUNT, 1),
      ]),
      Ttlv.encode_structure(Tag::BATCH_ITEM, batch_children),
    ])
  end

  def test_parse_response_extracts_operation_and_status
    response = build_mock_response(Operation::LOCATE, ResultStatus::SUCCESS, [
      Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, "id-1"),
    ])
    result = Operations.parse_response(response)
    assert_equal Operation::LOCATE, result[:operation]
    assert_equal ResultStatus::SUCCESS, result[:result_status]
  end

  def test_parse_response_raises_on_operation_failure
    batch_children = [
      Ttlv.encode_enum(Tag::OPERATION, Operation::GET),
      Ttlv.encode_enum(Tag::RESULT_STATUS, ResultStatus::OPERATION_FAILED),
      Ttlv.encode_text_string(Tag::RESULT_MESSAGE, "Item Not Found"),
    ]
    response = Ttlv.encode_structure(Tag::RESPONSE_MESSAGE, [
      Ttlv.encode_structure(Tag::RESPONSE_HEADER, [
        Ttlv.encode_structure(Tag::PROTOCOL_VERSION, [
          Ttlv.encode_integer(Tag::PROTOCOL_VERSION_MAJOR, 1),
          Ttlv.encode_integer(Tag::PROTOCOL_VERSION_MINOR, 4),
        ]),
        Ttlv.encode_integer(Tag::BATCH_COUNT, 1),
      ]),
      Ttlv.encode_structure(Tag::BATCH_ITEM, batch_children),
    ])
    error = assert_raises(RuntimeError) { Operations.parse_response(response) }
    assert_match(/Item Not Found/, error.message)
  end

  def test_parse_response_raises_on_non_response_message_tag
    bad_msg = Ttlv.encode_structure(Tag::REQUEST_MESSAGE, [])
    assert_raises(RuntimeError) { Operations.parse_response(bad_msg) }
  end

  def test_parse_locate_payload_extracts_unique_identifiers
    payload = Ttlv.decode(Ttlv.encode_structure(Tag::RESPONSE_PAYLOAD, [
      Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, "uid-1"),
      Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, "uid-2"),
      Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, "uid-3"),
    ]))
    result = Operations.parse_locate_payload(payload)
    assert_equal ["uid-1", "uid-2", "uid-3"], result[:unique_identifiers]
  end

  def test_parse_locate_payload_handles_empty_result
    payload = Ttlv.decode(Ttlv.encode_structure(Tag::RESPONSE_PAYLOAD, []))
    result = Operations.parse_locate_payload(payload)
    assert_equal [], result[:unique_identifiers]
  end

  def test_parse_locate_payload_handles_single_result
    payload = Ttlv.decode(Ttlv.encode_structure(Tag::RESPONSE_PAYLOAD, [
      Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, "only-one"),
    ]))
    result = Operations.parse_locate_payload(payload)
    assert_equal ["only-one"], result[:unique_identifiers]
  end

  def test_parse_get_payload_extracts_key_material
    key_bytes = ["0123456789abcdef0123456789abcdef"].pack("H*")
    payload = Ttlv.decode(Ttlv.encode_structure(Tag::RESPONSE_PAYLOAD, [
      Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, "uid-99"),
      Ttlv.encode_enum(Tag::OBJECT_TYPE, ObjectType::SYMMETRIC_KEY),
      Ttlv.encode_structure(Tag::SYMMETRIC_KEY, [
        Ttlv.encode_structure(Tag::KEY_BLOCK, [
          Ttlv.encode_enum(Tag::KEY_FORMAT_TYPE, 0x01), # Raw
          Ttlv.encode_structure(Tag::KEY_VALUE, [
            Ttlv.encode_byte_string(Tag::KEY_MATERIAL, key_bytes),
          ]),
        ]),
      ]),
    ]))
    result = Operations.parse_get_payload(payload)
    assert_equal "uid-99", result[:unique_identifier]
    assert_equal ObjectType::SYMMETRIC_KEY, result[:object_type]
    assert_equal key_bytes, result[:key_material]
  end

  def test_parse_get_payload_returns_nil_key_material_when_no_symmetric_key
    payload = Ttlv.decode(Ttlv.encode_structure(Tag::RESPONSE_PAYLOAD, [
      Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, "uid-50"),
      Ttlv.encode_enum(Tag::OBJECT_TYPE, ObjectType::CERTIFICATE),
    ]))
    result = Operations.parse_get_payload(payload)
    assert_equal "uid-50", result[:unique_identifier]
    assert_nil result[:key_material]
  end

  def test_parse_create_payload_extracts_object_type_and_uid
    payload = Ttlv.decode(Ttlv.encode_structure(Tag::RESPONSE_PAYLOAD, [
      Ttlv.encode_enum(Tag::OBJECT_TYPE, ObjectType::SYMMETRIC_KEY),
      Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, "new-uid-7"),
    ]))
    result = Operations.parse_create_payload(payload)
    assert_equal ObjectType::SYMMETRIC_KEY, result[:object_type]
    assert_equal "new-uid-7", result[:unique_identifier]
  end

  # ---------------------------------------------------------------------------
  # Round-trip: build -> encode -> decode -> verify
  # ---------------------------------------------------------------------------

  def test_locate_request_round_trip
    request = Operations.build_locate_request("round-trip-key")
    re_encoded = Operations.build_locate_request("round-trip-key")
    assert_equal request, re_encoded
  end

  def test_get_request_round_trip
    request = Operations.build_get_request("uid-abc")
    decoded = Ttlv.decode(request)
    assert_equal Tag::REQUEST_MESSAGE, decoded[:tag]
    batch = Ttlv.find_child(decoded, Tag::BATCH_ITEM)
    payload = Ttlv.find_child(batch, Tag::REQUEST_PAYLOAD)
    uid = Ttlv.find_child(payload, Tag::UNIQUE_IDENTIFIER)
    assert_equal "uid-abc", uid[:value]
  end

  def test_create_request_round_trip
    request = Operations.build_create_request("rt-key", Algorithm::AES, 128)
    decoded = Ttlv.decode(request)
    assert_equal Tag::REQUEST_MESSAGE, decoded[:tag]
    batch = Ttlv.find_child(decoded, Tag::BATCH_ITEM)
    op = Ttlv.find_child(batch, Tag::OPERATION)
    assert_equal Operation::CREATE, op[:value]
  end

  # ---------------------------------------------------------------------------
  # Protocol constants
  # ---------------------------------------------------------------------------

  def test_protocol_major_is_1
    assert_equal 1, Operations::PROTOCOL_MAJOR
  end

  def test_protocol_minor_is_4
    assert_equal 4, Operations::PROTOCOL_MINOR
  end
end
