# frozen_string_literal: true

require "minitest/autorun"
require_relative "../lib/cyphera_kmip"

class TestOperations < Minitest::Test
  include CypheraKmip

  # ---------------------------------------------------------------------------
  # Helper: build a mock success response
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

  # Helper: decode a request and return the batch item
  def decode_batch(request)
    decoded = Ttlv.decode(request)
    Ttlv.find_child(decoded, Tag::BATCH_ITEM)
  end

  # Helper: get operation enum from a decoded request
  def extract_operation(request)
    batch = decode_batch(request)
    Ttlv.find_child(batch, Tag::OPERATION)[:value]
  end

  # Helper: get payload from a decoded request
  def extract_payload(request)
    batch = decode_batch(request)
    Ttlv.find_child(batch, Tag::REQUEST_PAYLOAD)
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

  # ---------------------------------------------------------------------------
  # Request header (common)
  # ---------------------------------------------------------------------------

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

  # ---------------------------------------------------------------------------
  # 1. Create
  # ---------------------------------------------------------------------------

  def test_build_create_request_produces_valid_ttlv
    request = Operations.build_create_request("new-key")
    decoded = Ttlv.decode(request)
    assert_equal Tag::REQUEST_MESSAGE, decoded[:tag]
  end

  def test_build_create_request_has_create_operation
    assert_equal Operation::CREATE, extract_operation(Operations.build_create_request("k"))
  end

  def test_build_create_request_uses_symmetric_key_object_type
    payload = extract_payload(Operations.build_create_request("k"))
    obj_type = Ttlv.find_child(payload, Tag::OBJECT_TYPE)
    assert_equal ObjectType::SYMMETRIC_KEY, obj_type[:value]
  end

  def test_build_create_request_defaults_to_aes
    payload = extract_payload(Operations.build_create_request("k"))
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
    payload = extract_payload(Operations.build_create_request("k"))
    tmpl = Ttlv.find_child(payload, Tag::TEMPLATE_ATTRIBUTE)
    attrs = Ttlv.find_children(tmpl, Tag::ATTRIBUTE)
    len_attr = attrs.find do |a|
      name = Ttlv.find_child(a, Tag::ATTRIBUTE_NAME)
      name && name[:value] == "Cryptographic Length"
    end
    len_value = Ttlv.find_child(len_attr, Tag::ATTRIBUTE_VALUE)
    assert_equal 256, len_value[:value]
  end

  def test_build_create_request_includes_encrypt_decrypt_usage_mask
    payload = extract_payload(Operations.build_create_request("k"))
    tmpl = Ttlv.find_child(payload, Tag::TEMPLATE_ATTRIBUTE)
    attrs = Ttlv.find_children(tmpl, Tag::ATTRIBUTE)
    usage_attr = attrs.find do |a|
      name = Ttlv.find_child(a, Tag::ATTRIBUTE_NAME)
      name && name[:value] == "Cryptographic Usage Mask"
    end
    usage_value = Ttlv.find_child(usage_attr, Tag::ATTRIBUTE_VALUE)
    assert_equal(UsageMask::ENCRYPT | UsageMask::DECRYPT, usage_value[:value])
  end

  def test_build_create_request_includes_key_name
    payload = extract_payload(Operations.build_create_request("prod-key"))
    tmpl = Ttlv.find_child(payload, Tag::TEMPLATE_ATTRIBUTE)
    attrs = Ttlv.find_children(tmpl, Tag::ATTRIBUTE)
    name_attr = attrs.find do |a|
      name = Ttlv.find_child(a, Tag::ATTRIBUTE_NAME)
      name && name[:value] == "Name"
    end
    name_struct = Ttlv.find_child(name_attr, Tag::ATTRIBUTE_VALUE)
    name_value = Ttlv.find_child(name_struct, Tag::NAME_VALUE)
    assert_equal "prod-key", name_value[:value]
  end

  def test_build_create_request_custom_algorithm_and_length
    request = Operations.build_create_request("k", Algorithm::TRIPLE_DES, 192)
    payload = extract_payload(request)
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

  def test_parse_create_payload
    payload = Ttlv.decode(Ttlv.encode_structure(Tag::RESPONSE_PAYLOAD, [
      Ttlv.encode_enum(Tag::OBJECT_TYPE, ObjectType::SYMMETRIC_KEY),
      Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, "new-uid-7"),
    ]))
    result = Operations.parse_create_payload(payload)
    assert_equal ObjectType::SYMMETRIC_KEY, result[:object_type]
    assert_equal "new-uid-7", result[:unique_identifier]
  end

  # ---------------------------------------------------------------------------
  # 2. CreateKeyPair
  # ---------------------------------------------------------------------------

  def test_build_create_key_pair_request_has_correct_operation
    request = Operations.build_create_key_pair_request("kp", Algorithm::RSA, 2048)
    assert_equal Operation::CREATE_KEY_PAIR, extract_operation(request)
  end

  def test_build_create_key_pair_request_includes_sign_verify_usage_mask
    request = Operations.build_create_key_pair_request("kp", Algorithm::RSA, 2048)
    payload = extract_payload(request)
    tmpl = Ttlv.find_child(payload, Tag::TEMPLATE_ATTRIBUTE)
    attrs = Ttlv.find_children(tmpl, Tag::ATTRIBUTE)
    usage_attr = attrs.find do |a|
      name = Ttlv.find_child(a, Tag::ATTRIBUTE_NAME)
      name && name[:value] == "Cryptographic Usage Mask"
    end
    usage_value = Ttlv.find_child(usage_attr, Tag::ATTRIBUTE_VALUE)
    assert_equal(UsageMask::SIGN | UsageMask::VERIFY, usage_value[:value])
  end

  def test_parse_create_key_pair_payload
    payload = Ttlv.decode(Ttlv.encode_structure(Tag::RESPONSE_PAYLOAD, [
      Ttlv.encode_text_string(Tag::PRIVATE_KEY_UNIQUE_IDENTIFIER, "priv-1"),
      Ttlv.encode_text_string(Tag::PUBLIC_KEY_UNIQUE_IDENTIFIER, "pub-1"),
    ]))
    result = Operations.parse_create_key_pair_payload(payload)
    assert_equal "priv-1", result[:private_key_uid]
    assert_equal "pub-1", result[:public_key_uid]
  end

  # ---------------------------------------------------------------------------
  # 3. Register
  # ---------------------------------------------------------------------------

  def test_build_register_request_has_correct_operation
    material = "\x00" * 16
    request = Operations.build_register_request(ObjectType::SYMMETRIC_KEY, material, "reg-key", Algorithm::AES, 128)
    assert_equal Operation::REGISTER, extract_operation(request)
  end

  def test_build_register_request_includes_object_type
    material = "\x00" * 16
    request = Operations.build_register_request(ObjectType::SYMMETRIC_KEY, material, "reg-key", Algorithm::AES, 128)
    payload = extract_payload(request)
    obj_type = Ttlv.find_child(payload, Tag::OBJECT_TYPE)
    assert_equal ObjectType::SYMMETRIC_KEY, obj_type[:value]
  end

  def test_build_register_request_includes_key_material
    material = ("\xAB\xCD" * 8).b
    request = Operations.build_register_request(ObjectType::SYMMETRIC_KEY, material, "reg-key", Algorithm::AES, 128)
    payload = extract_payload(request)
    sym_key = Ttlv.find_child(payload, Tag::SYMMETRIC_KEY)
    key_block = Ttlv.find_child(sym_key, Tag::KEY_BLOCK)
    key_value = Ttlv.find_child(key_block, Tag::KEY_VALUE)
    key_mat = Ttlv.find_child(key_value, Tag::KEY_MATERIAL)
    assert_equal material, key_mat[:value]
  end

  def test_build_register_request_omits_name_when_empty
    material = "\x00" * 16
    request = Operations.build_register_request(ObjectType::SYMMETRIC_KEY, material, "", Algorithm::AES, 128)
    payload = extract_payload(request)
    tmpl = Ttlv.find_child(payload, Tag::TEMPLATE_ATTRIBUTE)
    assert_nil tmpl
  end

  # ---------------------------------------------------------------------------
  # 4. ReKey
  # ---------------------------------------------------------------------------

  def test_build_re_key_request_has_correct_operation
    assert_equal Operation::RE_KEY, extract_operation(Operations.build_re_key_request("uid-1"))
  end

  def test_build_re_key_request_contains_uid
    payload = extract_payload(Operations.build_re_key_request("uid-rk"))
    uid = Ttlv.find_child(payload, Tag::UNIQUE_IDENTIFIER)
    assert_equal "uid-rk", uid[:value]
  end

  def test_parse_re_key_payload
    payload = Ttlv.decode(Ttlv.encode_structure(Tag::RESPONSE_PAYLOAD, [
      Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, "new-uid"),
    ]))
    result = Operations.parse_re_key_payload(payload)
    assert_equal "new-uid", result[:unique_identifier]
  end

  # ---------------------------------------------------------------------------
  # 5. DeriveKey
  # ---------------------------------------------------------------------------

  def test_build_derive_key_request_has_correct_operation
    request = Operations.build_derive_key_request("uid", "\x01\x02".b, "derived", 256)
    assert_equal Operation::DERIVE_KEY, extract_operation(request)
  end

  def test_build_derive_key_request_contains_derivation_data
    request = Operations.build_derive_key_request("uid", "\xAA\xBB".b, "derived", 256)
    payload = extract_payload(request)
    params = Ttlv.find_child(payload, Tag::DERIVATION_PARAMETERS)
    data = Ttlv.find_child(params, Tag::DERIVATION_DATA)
    assert_equal "\xAA\xBB".b, data[:value]
  end

  def test_parse_derive_key_payload
    payload = Ttlv.decode(Ttlv.encode_structure(Tag::RESPONSE_PAYLOAD, [
      Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, "derived-uid"),
    ]))
    result = Operations.parse_derive_key_payload(payload)
    assert_equal "derived-uid", result[:unique_identifier]
  end

  # ---------------------------------------------------------------------------
  # 6. Locate
  # ---------------------------------------------------------------------------

  def test_build_locate_request_produces_valid_ttlv
    request = Operations.build_locate_request("test-key")
    decoded = Ttlv.decode(request)
    assert_equal Tag::REQUEST_MESSAGE, decoded[:tag]
  end

  def test_build_locate_request_has_locate_operation
    assert_equal Operation::LOCATE, extract_operation(Operations.build_locate_request("k"))
  end

  def test_build_locate_request_contains_name_attribute
    payload = extract_payload(Operations.build_locate_request("my-key"))
    attr = Ttlv.find_child(payload, Tag::ATTRIBUTE)
    attr_name = Ttlv.find_child(attr, Tag::ATTRIBUTE_NAME)
    assert_equal "Name", attr_name[:value]
    attr_value = Ttlv.find_child(attr, Tag::ATTRIBUTE_VALUE)
    name_value = Ttlv.find_child(attr_value, Tag::NAME_VALUE)
    assert_equal "my-key", name_value[:value]
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

  # ---------------------------------------------------------------------------
  # 7. Check
  # ---------------------------------------------------------------------------

  def test_build_check_request_has_correct_operation
    assert_equal Operation::CHECK, extract_operation(Operations.build_check_request("uid"))
  end

  def test_parse_check_payload
    payload = Ttlv.decode(Ttlv.encode_structure(Tag::RESPONSE_PAYLOAD, [
      Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, "check-uid"),
    ]))
    result = Operations.parse_check_payload(payload)
    assert_equal "check-uid", result[:unique_identifier]
  end

  def test_parse_check_payload_nil
    result = Operations.parse_check_payload(nil)
    assert_nil result[:unique_identifier]
  end

  # ---------------------------------------------------------------------------
  # 8. Get
  # ---------------------------------------------------------------------------

  def test_build_get_request_produces_valid_ttlv
    request = Operations.build_get_request("unique-id-123")
    decoded = Ttlv.decode(request)
    assert_equal Tag::REQUEST_MESSAGE, decoded[:tag]
  end

  def test_build_get_request_has_get_operation
    assert_equal Operation::GET, extract_operation(Operations.build_get_request("uid"))
  end

  def test_build_get_request_contains_unique_identifier
    payload = extract_payload(Operations.build_get_request("uid-456"))
    uid = Ttlv.find_child(payload, Tag::UNIQUE_IDENTIFIER)
    assert_equal "uid-456", uid[:value]
  end

  def test_parse_get_payload_extracts_key_material
    key_bytes = ["0123456789abcdef0123456789abcdef"].pack("H*")
    payload = Ttlv.decode(Ttlv.encode_structure(Tag::RESPONSE_PAYLOAD, [
      Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, "uid-99"),
      Ttlv.encode_enum(Tag::OBJECT_TYPE, ObjectType::SYMMETRIC_KEY),
      Ttlv.encode_structure(Tag::SYMMETRIC_KEY, [
        Ttlv.encode_structure(Tag::KEY_BLOCK, [
          Ttlv.encode_enum(Tag::KEY_FORMAT_TYPE, 0x01),
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
    assert_nil result[:key_material]
  end

  # ---------------------------------------------------------------------------
  # 9. GetAttributes
  # ---------------------------------------------------------------------------

  def test_build_get_attributes_request_has_correct_operation
    assert_equal Operation::GET_ATTRIBUTES, extract_operation(Operations.build_get_attributes_request("uid"))
  end

  def test_build_get_attributes_request_contains_uid
    payload = extract_payload(Operations.build_get_attributes_request("uid-ga"))
    uid = Ttlv.find_child(payload, Tag::UNIQUE_IDENTIFIER)
    assert_equal "uid-ga", uid[:value]
  end

  # ---------------------------------------------------------------------------
  # 10. GetAttributeList
  # ---------------------------------------------------------------------------

  def test_build_get_attribute_list_request_has_correct_operation
    assert_equal Operation::GET_ATTRIBUTE_LIST, extract_operation(Operations.build_get_attribute_list_request("uid"))
  end

  # ---------------------------------------------------------------------------
  # 11. AddAttribute
  # ---------------------------------------------------------------------------

  def test_build_add_attribute_request_has_correct_operation
    request = Operations.build_add_attribute_request("uid", "x-custom", "val")
    assert_equal Operation::ADD_ATTRIBUTE, extract_operation(request)
  end

  def test_build_add_attribute_request_contains_attribute
    request = Operations.build_add_attribute_request("uid-aa", "x-tag", "hello")
    payload = extract_payload(request)
    uid = Ttlv.find_child(payload, Tag::UNIQUE_IDENTIFIER)
    assert_equal "uid-aa", uid[:value]
    attr = Ttlv.find_child(payload, Tag::ATTRIBUTE)
    attr_name = Ttlv.find_child(attr, Tag::ATTRIBUTE_NAME)
    assert_equal "x-tag", attr_name[:value]
    attr_value = Ttlv.find_child(attr, Tag::ATTRIBUTE_VALUE)
    assert_equal "hello", attr_value[:value]
  end

  # ---------------------------------------------------------------------------
  # 12. ModifyAttribute
  # ---------------------------------------------------------------------------

  def test_build_modify_attribute_request_has_correct_operation
    request = Operations.build_modify_attribute_request("uid", "x-custom", "val")
    assert_equal Operation::MODIFY_ATTRIBUTE, extract_operation(request)
  end

  # ---------------------------------------------------------------------------
  # 13. DeleteAttribute
  # ---------------------------------------------------------------------------

  def test_build_delete_attribute_request_has_correct_operation
    request = Operations.build_delete_attribute_request("uid", "x-custom")
    assert_equal Operation::DELETE_ATTRIBUTE, extract_operation(request)
  end

  def test_build_delete_attribute_request_contains_attribute_name_only
    request = Operations.build_delete_attribute_request("uid-da", "x-tag")
    payload = extract_payload(request)
    attr = Ttlv.find_child(payload, Tag::ATTRIBUTE)
    attr_name = Ttlv.find_child(attr, Tag::ATTRIBUTE_NAME)
    assert_equal "x-tag", attr_name[:value]
    attr_value = Ttlv.find_child(attr, Tag::ATTRIBUTE_VALUE)
    assert_nil attr_value
  end

  # ---------------------------------------------------------------------------
  # 14. ObtainLease
  # ---------------------------------------------------------------------------

  def test_build_obtain_lease_request_has_correct_operation
    assert_equal Operation::OBTAIN_LEASE, extract_operation(Operations.build_obtain_lease_request("uid"))
  end

  # ---------------------------------------------------------------------------
  # 15. Activate
  # ---------------------------------------------------------------------------

  def test_build_activate_request_has_correct_operation
    assert_equal Operation::ACTIVATE, extract_operation(Operations.build_activate_request("uid"))
  end

  def test_build_activate_request_contains_uid
    payload = extract_payload(Operations.build_activate_request("uid-act"))
    uid = Ttlv.find_child(payload, Tag::UNIQUE_IDENTIFIER)
    assert_equal "uid-act", uid[:value]
  end

  # ---------------------------------------------------------------------------
  # 16. Revoke
  # ---------------------------------------------------------------------------

  def test_build_revoke_request_has_correct_operation
    assert_equal Operation::REVOKE, extract_operation(Operations.build_revoke_request("uid", 1))
  end

  def test_build_revoke_request_contains_revocation_reason
    request = Operations.build_revoke_request("uid-rev", 2)
    payload = extract_payload(request)
    reason = Ttlv.find_child(payload, Tag::REVOCATION_REASON)
    code = Ttlv.find_child(reason, Tag::REVOCATION_REASON_CODE)
    assert_equal 2, code[:value]
  end

  # ---------------------------------------------------------------------------
  # 17. Destroy
  # ---------------------------------------------------------------------------

  def test_build_destroy_request_has_correct_operation
    assert_equal Operation::DESTROY, extract_operation(Operations.build_destroy_request("uid"))
  end

  # ---------------------------------------------------------------------------
  # 18. Archive
  # ---------------------------------------------------------------------------

  def test_build_archive_request_has_correct_operation
    assert_equal Operation::ARCHIVE, extract_operation(Operations.build_archive_request("uid"))
  end

  # ---------------------------------------------------------------------------
  # 19. Recover
  # ---------------------------------------------------------------------------

  def test_build_recover_request_has_correct_operation
    assert_equal Operation::RECOVER, extract_operation(Operations.build_recover_request("uid"))
  end

  # ---------------------------------------------------------------------------
  # 20. Query
  # ---------------------------------------------------------------------------

  def test_build_query_request_has_correct_operation
    assert_equal Operation::QUERY, extract_operation(Operations.build_query_request)
  end

  def test_parse_query_payload
    payload = Ttlv.decode(Ttlv.encode_structure(Tag::RESPONSE_PAYLOAD, [
      Ttlv.encode_enum(Tag::OPERATION, Operation::CREATE),
      Ttlv.encode_enum(Tag::OPERATION, Operation::GET),
      Ttlv.encode_enum(Tag::OBJECT_TYPE, ObjectType::SYMMETRIC_KEY),
    ]))
    result = Operations.parse_query_payload(payload)
    assert_equal [Operation::CREATE, Operation::GET], result[:operations]
    assert_equal [ObjectType::SYMMETRIC_KEY], result[:object_types]
  end

  def test_parse_query_payload_nil
    result = Operations.parse_query_payload(nil)
    assert_equal [], result[:operations]
    assert_equal [], result[:object_types]
  end

  # ---------------------------------------------------------------------------
  # 21. Poll
  # ---------------------------------------------------------------------------

  def test_build_poll_request_has_correct_operation
    assert_equal Operation::POLL, extract_operation(Operations.build_poll_request)
  end

  # ---------------------------------------------------------------------------
  # 22. DiscoverVersions
  # ---------------------------------------------------------------------------

  def test_build_discover_versions_request_has_correct_operation
    assert_equal Operation::DISCOVER_VERSIONS, extract_operation(Operations.build_discover_versions_request)
  end

  def test_parse_discover_versions_payload
    payload = Ttlv.decode(Ttlv.encode_structure(Tag::RESPONSE_PAYLOAD, [
      Ttlv.encode_structure(Tag::PROTOCOL_VERSION, [
        Ttlv.encode_integer(Tag::PROTOCOL_VERSION_MAJOR, 1),
        Ttlv.encode_integer(Tag::PROTOCOL_VERSION_MINOR, 4),
      ]),
      Ttlv.encode_structure(Tag::PROTOCOL_VERSION, [
        Ttlv.encode_integer(Tag::PROTOCOL_VERSION_MAJOR, 1),
        Ttlv.encode_integer(Tag::PROTOCOL_VERSION_MINOR, 2),
      ]),
    ]))
    result = Operations.parse_discover_versions_payload(payload)
    assert_equal 2, result[:versions].size
    assert_equal({ major: 1, minor: 4 }, result[:versions][0])
    assert_equal({ major: 1, minor: 2 }, result[:versions][1])
  end

  def test_parse_discover_versions_payload_nil
    result = Operations.parse_discover_versions_payload(nil)
    assert_equal [], result[:versions]
  end

  # ---------------------------------------------------------------------------
  # 23. Encrypt
  # ---------------------------------------------------------------------------

  def test_build_encrypt_request_has_correct_operation
    request = Operations.build_encrypt_request("uid", "\x01\x02".b)
    assert_equal Operation::ENCRYPT, extract_operation(request)
  end

  def test_build_encrypt_request_contains_data
    request = Operations.build_encrypt_request("uid-enc", "\xAA\xBB".b)
    payload = extract_payload(request)
    data = Ttlv.find_child(payload, Tag::DATA)
    assert_equal "\xAA\xBB".b, data[:value]
  end

  def test_parse_encrypt_payload
    payload = Ttlv.decode(Ttlv.encode_structure(Tag::RESPONSE_PAYLOAD, [
      Ttlv.encode_byte_string(Tag::DATA, "\xCC\xDD".b),
      Ttlv.encode_byte_string(Tag::IV_COUNTER_NONCE, "\x11\x22".b),
    ]))
    result = Operations.parse_encrypt_payload(payload)
    assert_equal "\xCC\xDD".b, result[:data]
    assert_equal "\x11\x22".b, result[:nonce]
  end

  def test_parse_encrypt_payload_nil
    result = Operations.parse_encrypt_payload(nil)
    assert_nil result[:data]
    assert_nil result[:nonce]
  end

  # ---------------------------------------------------------------------------
  # 24. Decrypt
  # ---------------------------------------------------------------------------

  def test_build_decrypt_request_has_correct_operation
    request = Operations.build_decrypt_request("uid", "\x01\x02".b)
    assert_equal Operation::DECRYPT, extract_operation(request)
  end

  def test_build_decrypt_request_without_nonce
    request = Operations.build_decrypt_request("uid", "\x01\x02".b)
    payload = extract_payload(request)
    nonce = Ttlv.find_child(payload, Tag::IV_COUNTER_NONCE)
    assert_nil nonce
  end

  def test_build_decrypt_request_with_nonce
    request = Operations.build_decrypt_request("uid", "\x01\x02".b, "\xAA\xBB".b)
    payload = extract_payload(request)
    nonce = Ttlv.find_child(payload, Tag::IV_COUNTER_NONCE)
    assert_equal "\xAA\xBB".b, nonce[:value]
  end

  def test_parse_decrypt_payload
    payload = Ttlv.decode(Ttlv.encode_structure(Tag::RESPONSE_PAYLOAD, [
      Ttlv.encode_byte_string(Tag::DATA, "\xEE\xFF".b),
    ]))
    result = Operations.parse_decrypt_payload(payload)
    assert_equal "\xEE\xFF".b, result[:data]
  end

  # ---------------------------------------------------------------------------
  # 25. Sign
  # ---------------------------------------------------------------------------

  def test_build_sign_request_has_correct_operation
    request = Operations.build_sign_request("uid", "\x01\x02".b)
    assert_equal Operation::SIGN, extract_operation(request)
  end

  def test_build_sign_request_contains_data
    request = Operations.build_sign_request("uid-sign", "hello".b)
    payload = extract_payload(request)
    data = Ttlv.find_child(payload, Tag::DATA)
    assert_equal "hello".b, data[:value]
  end

  def test_parse_sign_payload
    payload = Ttlv.decode(Ttlv.encode_structure(Tag::RESPONSE_PAYLOAD, [
      Ttlv.encode_byte_string(Tag::SIGNATURE_DATA, "\xAA\xBB\xCC".b),
    ]))
    result = Operations.parse_sign_payload(payload)
    assert_equal "\xAA\xBB\xCC".b, result[:signature_data]
  end

  def test_parse_sign_payload_nil
    result = Operations.parse_sign_payload(nil)
    assert_nil result[:signature_data]
  end

  # ---------------------------------------------------------------------------
  # 26. SignatureVerify
  # ---------------------------------------------------------------------------

  def test_build_signature_verify_request_has_correct_operation
    request = Operations.build_signature_verify_request("uid", "\x01".b, "\x02".b)
    assert_equal Operation::SIGNATURE_VERIFY, extract_operation(request)
  end

  def test_build_signature_verify_request_contains_data_and_signature
    request = Operations.build_signature_verify_request("uid-sv", "msg".b, "sig".b)
    payload = extract_payload(request)
    data = Ttlv.find_child(payload, Tag::DATA)
    assert_equal "msg".b, data[:value]
    sig = Ttlv.find_child(payload, Tag::SIGNATURE_DATA)
    assert_equal "sig".b, sig[:value]
  end

  def test_parse_signature_verify_payload_valid
    payload = Ttlv.decode(Ttlv.encode_structure(Tag::RESPONSE_PAYLOAD, [
      Ttlv.encode_enum(Tag::VALIDITY_INDICATOR, 0),
    ]))
    result = Operations.parse_signature_verify_payload(payload)
    assert_equal true, result[:valid]
  end

  def test_parse_signature_verify_payload_invalid
    payload = Ttlv.decode(Ttlv.encode_structure(Tag::RESPONSE_PAYLOAD, [
      Ttlv.encode_enum(Tag::VALIDITY_INDICATOR, 1),
    ]))
    result = Operations.parse_signature_verify_payload(payload)
    assert_equal false, result[:valid]
  end

  # ---------------------------------------------------------------------------
  # 27. MAC
  # ---------------------------------------------------------------------------

  def test_build_mac_request_has_correct_operation
    request = Operations.build_mac_request("uid", "\x01\x02".b)
    assert_equal Operation::MAC, extract_operation(request)
  end

  def test_build_mac_request_contains_data
    request = Operations.build_mac_request("uid-mac", "data".b)
    payload = extract_payload(request)
    data = Ttlv.find_child(payload, Tag::DATA)
    assert_equal "data".b, data[:value]
  end

  def test_parse_mac_payload
    payload = Ttlv.decode(Ttlv.encode_structure(Tag::RESPONSE_PAYLOAD, [
      Ttlv.encode_byte_string(Tag::MAC_DATA, "\xDE\xAD".b),
    ]))
    result = Operations.parse_mac_payload(payload)
    assert_equal "\xDE\xAD".b, result[:mac_data]
  end

  def test_parse_mac_payload_nil
    result = Operations.parse_mac_payload(nil)
    assert_nil result[:mac_data]
  end

  # ---------------------------------------------------------------------------
  # Response parsing (common)
  # ---------------------------------------------------------------------------

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
  # All 27 operations produce valid TTLV RequestMessage
  # ---------------------------------------------------------------------------

  def test_all_uid_operations_produce_valid_ttlv
    uid_ops = {
      check: :build_check_request,
      activate: :build_activate_request,
      destroy: :build_destroy_request,
      re_key: :build_re_key_request,
      archive: :build_archive_request,
      recover: :build_recover_request,
      obtain_lease: :build_obtain_lease_request,
      get_attributes: :build_get_attributes_request,
      get_attribute_list: :build_get_attribute_list_request,
    }
    uid_ops.each do |name, method|
      request = Operations.send(method, "test-uid")
      decoded = Ttlv.decode(request)
      assert_equal Tag::REQUEST_MESSAGE, decoded[:tag], "#{name} did not produce RequestMessage"
    end
  end

  def test_all_empty_payload_operations_produce_valid_ttlv
    %i[build_query_request build_poll_request build_discover_versions_request].each do |method|
      request = Operations.send(method)
      decoded = Ttlv.decode(request)
      assert_equal Tag::REQUEST_MESSAGE, decoded[:tag], "#{method} did not produce RequestMessage"
    end
  end
end
