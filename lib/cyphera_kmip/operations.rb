# frozen_string_literal: true

module CypheraKmip
  # KMIP request/response builders for Locate, Get, Create operations.
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

    # Build a Locate request -- find keys by name.
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

    # Build a Get request -- fetch key material by unique ID.
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

    # Build a Create request -- create a new symmetric key.
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

    # Parse a KMIP response message.
    #
    # @param data [String] raw TTLV response bytes
    # @return [Hash] with keys: :operation, :result_status, :result_reason, :result_message, :payload
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

    # Parse a Locate response payload.
    #
    # @return [Hash] with key: :unique_identifiers (Array of String)
    def parse_locate_payload(payload)
      ids = Ttlv.find_children(payload, Tag::UNIQUE_IDENTIFIER)
      { unique_identifiers: ids.map { |id| id[:value] } }
    end

    # Parse a Get response payload.
    #
    # @return [Hash] with keys: :object_type, :unique_identifier, :key_material
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

    # Parse a Create response payload.
    #
    # @return [Hash] with keys: :object_type, :unique_identifier
    def parse_create_payload(payload)
      uid = Ttlv.find_child(payload, Tag::UNIQUE_IDENTIFIER)
      obj_type = Ttlv.find_child(payload, Tag::OBJECT_TYPE)
      {
        object_type: obj_type&.dig(:value),
        unique_identifier: uid&.dig(:value),
      }
    end
  end
end
