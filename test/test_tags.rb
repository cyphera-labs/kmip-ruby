# frozen_string_literal: true

require "minitest/autorun"
require_relative "../lib/cyphera_kmip"

class TestTags < Minitest::Test
  include CypheraKmip

  # ---------------------------------------------------------------------------
  # ObjectType values -- KMIP 1.4 Section 9.1.3.2.3
  # ---------------------------------------------------------------------------

  def test_object_type_certificate
    assert_equal 0x00000001, ObjectType::CERTIFICATE
  end

  def test_object_type_symmetric_key
    assert_equal 0x00000002, ObjectType::SYMMETRIC_KEY
  end

  def test_object_type_public_key
    assert_equal 0x00000003, ObjectType::PUBLIC_KEY
  end

  def test_object_type_private_key
    assert_equal 0x00000004, ObjectType::PRIVATE_KEY
  end

  def test_object_type_split_key
    assert_equal 0x00000005, ObjectType::SPLIT_KEY
  end

  def test_object_type_template
    assert_equal 0x00000006, ObjectType::TEMPLATE
  end

  def test_object_type_secret_data
    assert_equal 0x00000007, ObjectType::SECRET_DATA
  end

  def test_object_type_opaque_data
    assert_equal 0x00000008, ObjectType::OPAQUE_DATA
  end

  def test_object_type_no_duplicate_values
    values = object_type_values
    assert_equal values.size, values.uniq.size
  end

  # ---------------------------------------------------------------------------
  # Operation values -- KMIP 1.4 Section 9.1.3.2.2
  # ---------------------------------------------------------------------------

  def test_operation_create
    assert_equal 0x00000001, Operation::CREATE
  end

  def test_operation_locate
    assert_equal 0x00000008, Operation::LOCATE
  end

  def test_operation_get
    assert_equal 0x0000000A, Operation::GET
  end

  def test_operation_activate
    assert_equal 0x00000012, Operation::ACTIVATE
  end

  def test_operation_destroy
    assert_equal 0x00000014, Operation::DESTROY
  end

  def test_operation_check
    assert_equal 0x00000009, Operation::CHECK
  end

  def test_operation_no_duplicate_values
    values = operation_values
    assert_equal values.size, values.uniq.size
  end

  # ---------------------------------------------------------------------------
  # ResultStatus
  # ---------------------------------------------------------------------------

  def test_result_status_success
    assert_equal 0x00000000, ResultStatus::SUCCESS
  end

  def test_result_status_operation_failed
    assert_equal 0x00000001, ResultStatus::OPERATION_FAILED
  end

  def test_result_status_operation_pending
    assert_equal 0x00000002, ResultStatus::OPERATION_PENDING
  end

  def test_result_status_operation_undone
    assert_equal 0x00000003, ResultStatus::OPERATION_UNDONE
  end

  def test_result_status_no_duplicate_values
    values = result_status_values
    assert_equal values.size, values.uniq.size
  end

  # ---------------------------------------------------------------------------
  # Algorithm values -- KMIP 1.4 Section 9.1.3.2.13
  # ---------------------------------------------------------------------------

  def test_algorithm_des
    assert_equal 0x00000001, Algorithm::DES
  end

  def test_algorithm_triple_des
    assert_equal 0x00000002, Algorithm::TRIPLE_DES
  end

  def test_algorithm_aes
    assert_equal 0x00000003, Algorithm::AES
  end

  def test_algorithm_rsa
    assert_equal 0x00000004, Algorithm::RSA
  end

  def test_algorithm_dsa
    assert_equal 0x00000005, Algorithm::DSA
  end

  def test_algorithm_ecdsa
    assert_equal 0x00000006, Algorithm::ECDSA
  end

  def test_algorithm_hmac_sha1
    assert_equal 0x00000007, Algorithm::HMAC_SHA1
  end

  def test_algorithm_hmac_sha256
    assert_equal 0x00000008, Algorithm::HMAC_SHA256
  end

  def test_algorithm_hmac_sha384
    assert_equal 0x00000009, Algorithm::HMAC_SHA384
  end

  def test_algorithm_hmac_sha512
    assert_equal 0x0000000A, Algorithm::HMAC_SHA512
  end

  def test_algorithm_no_duplicate_values
    values = algorithm_values
    assert_equal values.size, values.uniq.size
  end

  # ---------------------------------------------------------------------------
  # KeyFormatType values
  # ---------------------------------------------------------------------------

  def test_key_format_type_raw
    assert_equal 0x00000001, KeyFormatType::RAW
  end

  def test_key_format_type_opaque
    assert_equal 0x00000002, KeyFormatType::OPAQUE
  end

  def test_key_format_type_pkcs1
    assert_equal 0x00000003, KeyFormatType::PKCS1
  end

  def test_key_format_type_pkcs8
    assert_equal 0x00000004, KeyFormatType::PKCS8
  end

  def test_key_format_type_x509
    assert_equal 0x00000005, KeyFormatType::X509
  end

  def test_key_format_type_ec_private_key
    assert_equal 0x00000006, KeyFormatType::EC_PRIVATE_KEY
  end

  def test_key_format_type_transparent_symmetric
    assert_equal 0x00000007, KeyFormatType::TRANSPARENT_SYMMETRIC
  end

  def test_key_format_type_no_duplicate_values
    values = key_format_type_values
    assert_equal values.size, values.uniq.size
  end

  # ---------------------------------------------------------------------------
  # NameType values
  # ---------------------------------------------------------------------------

  def test_name_type_uninterpreted_text_string
    assert_equal 0x00000001, NameType::UNINTERPRETED_TEXT_STRING
  end

  def test_name_type_uri
    assert_equal 0x00000002, NameType::URI
  end

  # ---------------------------------------------------------------------------
  # UsageMask -- bitmask values
  # ---------------------------------------------------------------------------

  def test_usage_mask_sign
    assert_equal 0x00000001, UsageMask::SIGN
  end

  def test_usage_mask_verify
    assert_equal 0x00000002, UsageMask::VERIFY
  end

  def test_usage_mask_encrypt
    assert_equal 0x00000004, UsageMask::ENCRYPT
  end

  def test_usage_mask_decrypt
    assert_equal 0x00000008, UsageMask::DECRYPT
  end

  def test_usage_mask_wrap_key
    assert_equal 0x00000010, UsageMask::WRAP_KEY
  end

  def test_usage_mask_unwrap_key
    assert_equal 0x00000020, UsageMask::UNWRAP_KEY
  end

  def test_usage_mask_export
    assert_equal 0x00000040, UsageMask::EXPORT
  end

  def test_usage_mask_derive_key
    assert_equal 0x00000100, UsageMask::DERIVE_KEY
  end

  def test_usage_mask_key_agreement
    assert_equal 0x00000800, UsageMask::KEY_AGREEMENT
  end

  def test_usage_mask_encrypt_or_decrypt_combines_correctly
    assert_equal 0x0000000C, UsageMask::ENCRYPT | UsageMask::DECRYPT
  end

  def test_usage_mask_all_values_are_distinct_powers_of_2
    values = usage_mask_values
    combined = 0
    values.each do |v|
      assert_equal 0, combined & v, "value 0x#{v.to_s(16)} overlaps with previous values"
      combined |= v
    end
  end

  # ---------------------------------------------------------------------------
  # Tag values -- all should be in the 0x42XXXX range
  # ---------------------------------------------------------------------------

  def test_all_tag_values_in_kmip_range
    tag_constants.each do |name, value|
      assert value >= 0x420000 && value <= 0x42FFFF,
             "Tag::#{name} = 0x#{value.to_s(16)} is outside 0x42XXXX range"
    end
  end

  def test_no_duplicate_tag_values
    values = tag_constants.values
    assert_equal values.size, values.uniq.size
  end

  private

  # Helpers to collect constant values from each module

  def tag_constants
    Tag.constants.each_with_object({}) do |name, hash|
      hash[name] = Tag.const_get(name)
    end
  end

  def object_type_values
    ObjectType.constants.map { |c| ObjectType.const_get(c) }
  end

  def operation_values
    Operation.constants.map { |c| Operation.const_get(c) }
  end

  def result_status_values
    ResultStatus.constants.map { |c| ResultStatus.const_get(c) }
  end

  def algorithm_values
    Algorithm.constants.map { |c| Algorithm.const_get(c) }
  end

  def key_format_type_values
    KeyFormatType.constants.map { |c| KeyFormatType.const_get(c) }
  end

  def usage_mask_values
    UsageMask.constants.map { |c| UsageMask.const_get(c) }
  end
end
