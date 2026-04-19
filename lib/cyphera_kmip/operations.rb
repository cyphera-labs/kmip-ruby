# frozen_string_literal: true

module CypheraKmip
  # KMIP request/response builders for all 27 KMIP 1.4 operations.
  module Operations
    # Protocol version: KMIP 1.4
    PROTOCOL_MAJOR = 1
    PROTOCOL_MINOR = 4

    module_function

    # Build the request header (included in every request).
    def build_request_header(batch_count = 1)
      Ttlv.encode_structure(Tag::REQUEST_HEADER, [
        Ttlv.encode_structure(Tag::PROTOCOL_VERSION, [
          Ttlv.encode_integer(Tag::PROTOCOL_VERSION_MAJOR, PROTOCOL_MAJOR),
          Ttlv.encode_integer(Tag::PROTOCOL_VERSION_MINOR, PROTOCOL_MINOR),
        ]),
        Ttlv.encode_integer(Tag::BATCH_COUNT, batch_count),
      ])
    end

    # -------------------------------------------------------------------------
    # Helper: wrap a payload + operation into a full RequestMessage.
    # -------------------------------------------------------------------------

    def build_uid_only_request(operation, unique_id)
      payload = Ttlv.encode_structure(Tag::REQUEST_PAYLOAD, [
        Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, unique_id),
      ])
      batch_item = Ttlv.encode_structure(Tag::BATCH_ITEM, [
        Ttlv.encode_enum(Tag::OPERATION, operation),
        payload,
      ])
      Ttlv.encode_structure(Tag::REQUEST_MESSAGE, [
        build_request_header,
        batch_item,
      ])
    end

    def build_empty_payload_request(operation)
      payload = Ttlv.encode_structure(Tag::REQUEST_PAYLOAD, [])
      batch_item = Ttlv.encode_structure(Tag::BATCH_ITEM, [
        Ttlv.encode_enum(Tag::OPERATION, operation),
        payload,
      ])
      Ttlv.encode_structure(Tag::REQUEST_MESSAGE, [
        build_request_header,
        batch_item,
      ])
    end

    # -------------------------------------------------------------------------
    # 1. Create
    # -------------------------------------------------------------------------

    def build_create_request(name, algorithm = Algorithm::AES, length = 256)
      usage_mask = UsageMask::ENCRYPT | UsageMask::DECRYPT

      payload = Ttlv.encode_structure(Tag::REQUEST_PAYLOAD, [
        Ttlv.encode_enum(Tag::OBJECT_TYPE, ObjectType::SYMMETRIC_KEY),
        Ttlv.encode_structure(Tag::TEMPLATE_ATTRIBUTE, [
          Ttlv.encode_structure(Tag::ATTRIBUTE, [
            Ttlv.encode_text_string(Tag::ATTRIBUTE_NAME, "Cryptographic Algorithm"),
            Ttlv.encode_enum(Tag::ATTRIBUTE_VALUE, algorithm),
          ]),
          Ttlv.encode_structure(Tag::ATTRIBUTE, [
            Ttlv.encode_text_string(Tag::ATTRIBUTE_NAME, "Cryptographic Length"),
            Ttlv.encode_integer(Tag::ATTRIBUTE_VALUE, length),
          ]),
          Ttlv.encode_structure(Tag::ATTRIBUTE, [
            Ttlv.encode_text_string(Tag::ATTRIBUTE_NAME, "Cryptographic Usage Mask"),
            Ttlv.encode_integer(Tag::ATTRIBUTE_VALUE, usage_mask),
          ]),
          Ttlv.encode_structure(Tag::ATTRIBUTE, [
            Ttlv.encode_text_string(Tag::ATTRIBUTE_NAME, "Name"),
            Ttlv.encode_structure(Tag::ATTRIBUTE_VALUE, [
              Ttlv.encode_text_string(Tag::NAME_VALUE, name),
              Ttlv.encode_enum(Tag::NAME_TYPE, NameType::UNINTERPRETED_TEXT_STRING),
            ]),
          ]),
        ]),
      ])

      batch_item = Ttlv.encode_structure(Tag::BATCH_ITEM, [
        Ttlv.encode_enum(Tag::OPERATION, Operation::CREATE),
        payload,
      ])

      Ttlv.encode_structure(Tag::REQUEST_MESSAGE, [
        build_request_header,
        batch_item,
      ])
    end

    def parse_create_payload(payload)
      uid = Ttlv.find_child(payload, Tag::UNIQUE_IDENTIFIER)
      obj_type = Ttlv.find_child(payload, Tag::OBJECT_TYPE)
      {
        object_type: obj_type&.dig(:value),
        unique_identifier: uid&.dig(:value),
      }
    end

    # -------------------------------------------------------------------------
    # 2. CreateKeyPair
    # -------------------------------------------------------------------------

    def build_create_key_pair_request(name, algorithm, length)
      payload = Ttlv.encode_structure(Tag::REQUEST_PAYLOAD, [
        Ttlv.encode_structure(Tag::TEMPLATE_ATTRIBUTE, [
          Ttlv.encode_structure(Tag::ATTRIBUTE, [
            Ttlv.encode_text_string(Tag::ATTRIBUTE_NAME, "Cryptographic Algorithm"),
            Ttlv.encode_enum(Tag::ATTRIBUTE_VALUE, algorithm),
          ]),
          Ttlv.encode_structure(Tag::ATTRIBUTE, [
            Ttlv.encode_text_string(Tag::ATTRIBUTE_NAME, "Cryptographic Length"),
            Ttlv.encode_integer(Tag::ATTRIBUTE_VALUE, length),
          ]),
          Ttlv.encode_structure(Tag::ATTRIBUTE, [
            Ttlv.encode_text_string(Tag::ATTRIBUTE_NAME, "Cryptographic Usage Mask"),
            Ttlv.encode_integer(Tag::ATTRIBUTE_VALUE, UsageMask::SIGN | UsageMask::VERIFY),
          ]),
          Ttlv.encode_structure(Tag::ATTRIBUTE, [
            Ttlv.encode_text_string(Tag::ATTRIBUTE_NAME, "Name"),
            Ttlv.encode_structure(Tag::ATTRIBUTE_VALUE, [
              Ttlv.encode_text_string(Tag::NAME_VALUE, name),
              Ttlv.encode_enum(Tag::NAME_TYPE, NameType::UNINTERPRETED_TEXT_STRING),
            ]),
          ]),
        ]),
      ])
      batch_item = Ttlv.encode_structure(Tag::BATCH_ITEM, [
        Ttlv.encode_enum(Tag::OPERATION, Operation::CREATE_KEY_PAIR),
        payload,
      ])
      Ttlv.encode_structure(Tag::REQUEST_MESSAGE, [
        build_request_header,
        batch_item,
      ])
    end

    def parse_create_key_pair_payload(payload)
      result = { private_key_uid: nil, public_key_uid: nil }
      return result if payload.nil?

      priv = Ttlv.find_child(payload, Tag::PRIVATE_KEY_UNIQUE_IDENTIFIER)
      pub = Ttlv.find_child(payload, Tag::PUBLIC_KEY_UNIQUE_IDENTIFIER)
      result[:private_key_uid] = priv[:value] if priv
      result[:public_key_uid] = pub[:value] if pub
      result
    end

    # -------------------------------------------------------------------------
    # 3. Register
    # -------------------------------------------------------------------------

    def build_register_request(object_type, material, name, algorithm, length)
      payload_children = [
        Ttlv.encode_enum(Tag::OBJECT_TYPE, object_type),
        Ttlv.encode_structure(Tag::SYMMETRIC_KEY, [
          Ttlv.encode_structure(Tag::KEY_BLOCK, [
            Ttlv.encode_enum(Tag::KEY_FORMAT_TYPE, KeyFormatType::RAW),
            Ttlv.encode_structure(Tag::KEY_VALUE, [
              Ttlv.encode_byte_string(Tag::KEY_MATERIAL, material),
            ]),
            Ttlv.encode_enum(Tag::CRYPTOGRAPHIC_ALGORITHM, algorithm),
            Ttlv.encode_integer(Tag::CRYPTOGRAPHIC_LENGTH, length),
          ]),
        ]),
      ]
      unless name.nil? || name.empty?
        payload_children << Ttlv.encode_structure(Tag::TEMPLATE_ATTRIBUTE, [
          Ttlv.encode_structure(Tag::ATTRIBUTE, [
            Ttlv.encode_text_string(Tag::ATTRIBUTE_NAME, "Name"),
            Ttlv.encode_structure(Tag::ATTRIBUTE_VALUE, [
              Ttlv.encode_text_string(Tag::NAME_VALUE, name),
              Ttlv.encode_enum(Tag::NAME_TYPE, NameType::UNINTERPRETED_TEXT_STRING),
            ]),
          ]),
        ])
      end
      payload = Ttlv.encode_structure(Tag::REQUEST_PAYLOAD, payload_children)
      batch_item = Ttlv.encode_structure(Tag::BATCH_ITEM, [
        Ttlv.encode_enum(Tag::OPERATION, Operation::REGISTER),
        payload,
      ])
      Ttlv.encode_structure(Tag::REQUEST_MESSAGE, [
        build_request_header,
        batch_item,
      ])
    end

    # -------------------------------------------------------------------------
    # 4. ReKey
    # -------------------------------------------------------------------------

    def build_re_key_request(unique_id)
      build_uid_only_request(Operation::RE_KEY, unique_id)
    end

    def parse_re_key_payload(payload)
      result = { unique_identifier: nil }
      return result if payload.nil?

      uid = Ttlv.find_child(payload, Tag::UNIQUE_IDENTIFIER)
      result[:unique_identifier] = uid[:value] if uid
      result
    end

    # -------------------------------------------------------------------------
    # 5. DeriveKey
    # -------------------------------------------------------------------------

    def build_derive_key_request(unique_id, derivation_data, name, length)
      payload = Ttlv.encode_structure(Tag::REQUEST_PAYLOAD, [
        Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, unique_id),
        Ttlv.encode_structure(Tag::DERIVATION_PARAMETERS, [
          Ttlv.encode_byte_string(Tag::DERIVATION_DATA, derivation_data),
        ]),
        Ttlv.encode_structure(Tag::TEMPLATE_ATTRIBUTE, [
          Ttlv.encode_structure(Tag::ATTRIBUTE, [
            Ttlv.encode_text_string(Tag::ATTRIBUTE_NAME, "Cryptographic Length"),
            Ttlv.encode_integer(Tag::ATTRIBUTE_VALUE, length),
          ]),
          Ttlv.encode_structure(Tag::ATTRIBUTE, [
            Ttlv.encode_text_string(Tag::ATTRIBUTE_NAME, "Name"),
            Ttlv.encode_structure(Tag::ATTRIBUTE_VALUE, [
              Ttlv.encode_text_string(Tag::NAME_VALUE, name),
              Ttlv.encode_enum(Tag::NAME_TYPE, NameType::UNINTERPRETED_TEXT_STRING),
            ]),
          ]),
        ]),
      ])
      batch_item = Ttlv.encode_structure(Tag::BATCH_ITEM, [
        Ttlv.encode_enum(Tag::OPERATION, Operation::DERIVE_KEY),
        payload,
      ])
      Ttlv.encode_structure(Tag::REQUEST_MESSAGE, [
        build_request_header,
        batch_item,
      ])
    end

    def parse_derive_key_payload(payload)
      result = { unique_identifier: nil }
      return result if payload.nil?

      uid = Ttlv.find_child(payload, Tag::UNIQUE_IDENTIFIER)
      result[:unique_identifier] = uid[:value] if uid
      result
    end

    # -------------------------------------------------------------------------
    # 6. Locate
    # -------------------------------------------------------------------------

    def build_locate_request(name)
      payload = Ttlv.encode_structure(Tag::REQUEST_PAYLOAD, [
        Ttlv.encode_structure(Tag::ATTRIBUTE, [
          Ttlv.encode_text_string(Tag::ATTRIBUTE_NAME, "Name"),
          Ttlv.encode_structure(Tag::ATTRIBUTE_VALUE, [
            Ttlv.encode_text_string(Tag::NAME_VALUE, name),
            Ttlv.encode_enum(Tag::NAME_TYPE, NameType::UNINTERPRETED_TEXT_STRING),
          ]),
        ]),
      ])

      batch_item = Ttlv.encode_structure(Tag::BATCH_ITEM, [
        Ttlv.encode_enum(Tag::OPERATION, Operation::LOCATE),
        payload,
      ])

      Ttlv.encode_structure(Tag::REQUEST_MESSAGE, [
        build_request_header,
        batch_item,
      ])
    end

    def parse_locate_payload(payload)
      ids = Ttlv.find_children(payload, Tag::UNIQUE_IDENTIFIER)
      { unique_identifiers: ids.map { |id| id[:value] } }
    end

    # -------------------------------------------------------------------------
    # 7. Check
    # -------------------------------------------------------------------------

    def build_check_request(unique_id)
      build_uid_only_request(Operation::CHECK, unique_id)
    end

    def parse_check_payload(payload)
      result = { unique_identifier: nil }
      return result if payload.nil?

      uid = Ttlv.find_child(payload, Tag::UNIQUE_IDENTIFIER)
      result[:unique_identifier] = uid[:value] if uid
      result
    end

    # -------------------------------------------------------------------------
    # 8. Get
    # -------------------------------------------------------------------------

    def build_get_request(unique_id)
      payload = Ttlv.encode_structure(Tag::REQUEST_PAYLOAD, [
        Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, unique_id),
      ])

      batch_item = Ttlv.encode_structure(Tag::BATCH_ITEM, [
        Ttlv.encode_enum(Tag::OPERATION, Operation::GET),
        payload,
      ])

      Ttlv.encode_structure(Tag::REQUEST_MESSAGE, [
        build_request_header,
        batch_item,
      ])
    end

    def parse_get_payload(payload)
      uid = Ttlv.find_child(payload, Tag::UNIQUE_IDENTIFIER)
      obj_type = Ttlv.find_child(payload, Tag::OBJECT_TYPE)

      # Navigate: SymmetricKey -> KeyBlock -> KeyValue -> KeyMaterial
      key_material = nil
      sym_key = Ttlv.find_child(payload, Tag::SYMMETRIC_KEY)
      if sym_key
        key_block = Ttlv.find_child(sym_key, Tag::KEY_BLOCK)
        if key_block
          key_value = Ttlv.find_child(key_block, Tag::KEY_VALUE)
          if key_value
            material = Ttlv.find_child(key_value, Tag::KEY_MATERIAL)
            key_material = material[:value] if material
          end
        end
      end

      {
        object_type: obj_type&.dig(:value),
        unique_identifier: uid&.dig(:value),
        key_material: key_material,
      }
    end

    # -------------------------------------------------------------------------
    # 9. GetAttributes
    # -------------------------------------------------------------------------

    def build_get_attributes_request(unique_id)
      build_uid_only_request(Operation::GET_ATTRIBUTES, unique_id)
    end

    # -------------------------------------------------------------------------
    # 10. GetAttributeList
    # -------------------------------------------------------------------------

    def build_get_attribute_list_request(unique_id)
      build_uid_only_request(Operation::GET_ATTRIBUTE_LIST, unique_id)
    end

    # -------------------------------------------------------------------------
    # 11. AddAttribute
    # -------------------------------------------------------------------------

    def build_add_attribute_request(unique_id, attr_name, attr_value)
      payload = Ttlv.encode_structure(Tag::REQUEST_PAYLOAD, [
        Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, unique_id),
        Ttlv.encode_structure(Tag::ATTRIBUTE, [
          Ttlv.encode_text_string(Tag::ATTRIBUTE_NAME, attr_name),
          Ttlv.encode_text_string(Tag::ATTRIBUTE_VALUE, attr_value),
        ]),
      ])
      batch_item = Ttlv.encode_structure(Tag::BATCH_ITEM, [
        Ttlv.encode_enum(Tag::OPERATION, Operation::ADD_ATTRIBUTE),
        payload,
      ])
      Ttlv.encode_structure(Tag::REQUEST_MESSAGE, [
        build_request_header,
        batch_item,
      ])
    end

    # -------------------------------------------------------------------------
    # 12. ModifyAttribute
    # -------------------------------------------------------------------------

    def build_modify_attribute_request(unique_id, attr_name, attr_value)
      payload = Ttlv.encode_structure(Tag::REQUEST_PAYLOAD, [
        Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, unique_id),
        Ttlv.encode_structure(Tag::ATTRIBUTE, [
          Ttlv.encode_text_string(Tag::ATTRIBUTE_NAME, attr_name),
          Ttlv.encode_text_string(Tag::ATTRIBUTE_VALUE, attr_value),
        ]),
      ])
      batch_item = Ttlv.encode_structure(Tag::BATCH_ITEM, [
        Ttlv.encode_enum(Tag::OPERATION, Operation::MODIFY_ATTRIBUTE),
        payload,
      ])
      Ttlv.encode_structure(Tag::REQUEST_MESSAGE, [
        build_request_header,
        batch_item,
      ])
    end

    # -------------------------------------------------------------------------
    # 13. DeleteAttribute
    # -------------------------------------------------------------------------

    def build_delete_attribute_request(unique_id, attr_name)
      payload = Ttlv.encode_structure(Tag::REQUEST_PAYLOAD, [
        Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, unique_id),
        Ttlv.encode_structure(Tag::ATTRIBUTE, [
          Ttlv.encode_text_string(Tag::ATTRIBUTE_NAME, attr_name),
        ]),
      ])
      batch_item = Ttlv.encode_structure(Tag::BATCH_ITEM, [
        Ttlv.encode_enum(Tag::OPERATION, Operation::DELETE_ATTRIBUTE),
        payload,
      ])
      Ttlv.encode_structure(Tag::REQUEST_MESSAGE, [
        build_request_header,
        batch_item,
      ])
    end

    # -------------------------------------------------------------------------
    # 14. ObtainLease
    # -------------------------------------------------------------------------

    def build_obtain_lease_request(unique_id)
      build_uid_only_request(Operation::OBTAIN_LEASE, unique_id)
    end

    # -------------------------------------------------------------------------
    # 15. Activate
    # -------------------------------------------------------------------------

    def build_activate_request(unique_id)
      build_uid_only_request(Operation::ACTIVATE, unique_id)
    end

    # -------------------------------------------------------------------------
    # 16. Revoke
    # -------------------------------------------------------------------------

    def build_revoke_request(unique_id, reason)
      payload = Ttlv.encode_structure(Tag::REQUEST_PAYLOAD, [
        Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, unique_id),
        Ttlv.encode_structure(Tag::REVOCATION_REASON, [
          Ttlv.encode_enum(Tag::REVOCATION_REASON_CODE, reason),
        ]),
      ])
      batch_item = Ttlv.encode_structure(Tag::BATCH_ITEM, [
        Ttlv.encode_enum(Tag::OPERATION, Operation::REVOKE),
        payload,
      ])
      Ttlv.encode_structure(Tag::REQUEST_MESSAGE, [
        build_request_header,
        batch_item,
      ])
    end

    # -------------------------------------------------------------------------
    # 17. Destroy
    # -------------------------------------------------------------------------

    def build_destroy_request(unique_id)
      build_uid_only_request(Operation::DESTROY, unique_id)
    end

    # -------------------------------------------------------------------------
    # 18. Archive
    # -------------------------------------------------------------------------

    def build_archive_request(unique_id)
      build_uid_only_request(Operation::ARCHIVE, unique_id)
    end

    # -------------------------------------------------------------------------
    # 19. Recover
    # -------------------------------------------------------------------------

    def build_recover_request(unique_id)
      build_uid_only_request(Operation::RECOVER, unique_id)
    end

    # -------------------------------------------------------------------------
    # 20. Query
    # -------------------------------------------------------------------------

    def build_query_request
      build_empty_payload_request(Operation::QUERY)
    end

    def parse_query_payload(payload)
      result = { operations: [], object_types: [] }
      return result if payload.nil?

      ops = Ttlv.find_children(payload, Tag::OPERATION)
      ops.each { |op| result[:operations] << op[:value] }
      obj_types = Ttlv.find_children(payload, Tag::OBJECT_TYPE)
      obj_types.each { |ot| result[:object_types] << ot[:value] }
      result
    end

    # -------------------------------------------------------------------------
    # 21. Poll
    # -------------------------------------------------------------------------

    def build_poll_request
      build_empty_payload_request(Operation::POLL)
    end

    # -------------------------------------------------------------------------
    # 22. DiscoverVersions
    # -------------------------------------------------------------------------

    def build_discover_versions_request
      build_empty_payload_request(Operation::DISCOVER_VERSIONS)
    end

    def parse_discover_versions_payload(payload)
      result = { versions: [] }
      return result if payload.nil?

      versions = Ttlv.find_children(payload, Tag::PROTOCOL_VERSION)
      versions.each do |v|
        major = Ttlv.find_child(v, Tag::PROTOCOL_VERSION_MAJOR)
        minor = Ttlv.find_child(v, Tag::PROTOCOL_VERSION_MINOR)
        entry = { major: 0, minor: 0 }
        entry[:major] = major[:value] if major
        entry[:minor] = minor[:value] if minor
        result[:versions] << entry
      end
      result
    end

    # -------------------------------------------------------------------------
    # 23. Encrypt
    # -------------------------------------------------------------------------

    def build_encrypt_request(unique_id, data)
      payload = Ttlv.encode_structure(Tag::REQUEST_PAYLOAD, [
        Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, unique_id),
        Ttlv.encode_byte_string(Tag::DATA, data),
      ])
      batch_item = Ttlv.encode_structure(Tag::BATCH_ITEM, [
        Ttlv.encode_enum(Tag::OPERATION, Operation::ENCRYPT),
        payload,
      ])
      Ttlv.encode_structure(Tag::REQUEST_MESSAGE, [
        build_request_header,
        batch_item,
      ])
    end

    def parse_encrypt_payload(payload)
      result = { data: nil, nonce: nil }
      return result if payload.nil?

      data = Ttlv.find_child(payload, Tag::DATA)
      result[:data] = data[:value] if data
      nonce = Ttlv.find_child(payload, Tag::IV_COUNTER_NONCE)
      result[:nonce] = nonce[:value] if nonce
      result
    end

    # -------------------------------------------------------------------------
    # 24. Decrypt
    # -------------------------------------------------------------------------

    def build_decrypt_request(unique_id, data, nonce = nil)
      payload_children = [
        Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, unique_id),
        Ttlv.encode_byte_string(Tag::DATA, data),
      ]
      if nonce && !nonce.empty?
        payload_children << Ttlv.encode_byte_string(Tag::IV_COUNTER_NONCE, nonce)
      end
      payload = Ttlv.encode_structure(Tag::REQUEST_PAYLOAD, payload_children)
      batch_item = Ttlv.encode_structure(Tag::BATCH_ITEM, [
        Ttlv.encode_enum(Tag::OPERATION, Operation::DECRYPT),
        payload,
      ])
      Ttlv.encode_structure(Tag::REQUEST_MESSAGE, [
        build_request_header,
        batch_item,
      ])
    end

    def parse_decrypt_payload(payload)
      result = { data: nil }
      return result if payload.nil?

      data = Ttlv.find_child(payload, Tag::DATA)
      result[:data] = data[:value] if data
      result
    end

    # -------------------------------------------------------------------------
    # 25. Sign
    # -------------------------------------------------------------------------

    def build_sign_request(unique_id, data)
      payload = Ttlv.encode_structure(Tag::REQUEST_PAYLOAD, [
        Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, unique_id),
        Ttlv.encode_byte_string(Tag::DATA, data),
      ])
      batch_item = Ttlv.encode_structure(Tag::BATCH_ITEM, [
        Ttlv.encode_enum(Tag::OPERATION, Operation::SIGN),
        payload,
      ])
      Ttlv.encode_structure(Tag::REQUEST_MESSAGE, [
        build_request_header,
        batch_item,
      ])
    end

    def parse_sign_payload(payload)
      result = { signature_data: nil }
      return result if payload.nil?

      sig = Ttlv.find_child(payload, Tag::SIGNATURE_DATA)
      result[:signature_data] = sig[:value] if sig
      result
    end

    # -------------------------------------------------------------------------
    # 26. SignatureVerify
    # -------------------------------------------------------------------------

    def build_signature_verify_request(unique_id, data, signature)
      payload = Ttlv.encode_structure(Tag::REQUEST_PAYLOAD, [
        Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, unique_id),
        Ttlv.encode_byte_string(Tag::DATA, data),
        Ttlv.encode_byte_string(Tag::SIGNATURE_DATA, signature),
      ])
      batch_item = Ttlv.encode_structure(Tag::BATCH_ITEM, [
        Ttlv.encode_enum(Tag::OPERATION, Operation::SIGNATURE_VERIFY),
        payload,
      ])
      Ttlv.encode_structure(Tag::REQUEST_MESSAGE, [
        build_request_header,
        batch_item,
      ])
    end

    def parse_signature_verify_payload(payload)
      result = { valid: false }
      return result if payload.nil?

      indicator = Ttlv.find_child(payload, Tag::VALIDITY_INDICATOR)
      # 0 = Valid, 1 = Invalid (matches Go reference)
      result[:valid] = (indicator[:value] == 0) if indicator
      result
    end

    # -------------------------------------------------------------------------
    # 27. MAC
    # -------------------------------------------------------------------------

    def build_mac_request(unique_id, data)
      payload = Ttlv.encode_structure(Tag::REQUEST_PAYLOAD, [
        Ttlv.encode_text_string(Tag::UNIQUE_IDENTIFIER, unique_id),
        Ttlv.encode_byte_string(Tag::DATA, data),
      ])
      batch_item = Ttlv.encode_structure(Tag::BATCH_ITEM, [
        Ttlv.encode_enum(Tag::OPERATION, Operation::MAC),
        payload,
      ])
      Ttlv.encode_structure(Tag::REQUEST_MESSAGE, [
        build_request_header,
        batch_item,
      ])
    end

    def parse_mac_payload(payload)
      result = { mac_data: nil }
      return result if payload.nil?

      mac = Ttlv.find_child(payload, Tag::MAC_DATA)
      result[:mac_data] = mac[:value] if mac
      result
    end

    # -------------------------------------------------------------------------
    # Response parsing (common to all operations)
    # -------------------------------------------------------------------------

    def parse_response(data)
      msg = Ttlv.decode(data)
      unless msg[:tag] == Tag::RESPONSE_MESSAGE
        raise "Expected ResponseMessage (0x42007B), got 0x#{msg[:tag].to_s(16).rjust(6, '0')}"
      end

      batch_item = Ttlv.find_child(msg, Tag::BATCH_ITEM)
      raise "No BatchItem in response" if batch_item.nil?

      operation_item = Ttlv.find_child(batch_item, Tag::OPERATION)
      status_item = Ttlv.find_child(batch_item, Tag::RESULT_STATUS)
      reason_item = Ttlv.find_child(batch_item, Tag::RESULT_REASON)
      message_item = Ttlv.find_child(batch_item, Tag::RESULT_MESSAGE)
      payload_item = Ttlv.find_child(batch_item, Tag::RESPONSE_PAYLOAD)

      result = {
        operation: operation_item&.dig(:value),
        result_status: status_item&.dig(:value),
        result_reason: reason_item&.dig(:value),
        result_message: message_item&.dig(:value),
        payload: payload_item,
      }

      unless result[:result_status] == ResultStatus::SUCCESS
        error_msg = result[:result_message] || "KMIP operation failed (status=#{result[:result_status]})"
        raise error_msg
      end

      result
    end
  end
end
