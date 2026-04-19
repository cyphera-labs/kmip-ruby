# frozen_string_literal: true

module CypheraKmip
  # TTLV (Tag-Type-Length-Value) encoder/decoder for KMIP.
  # Implements the OASIS KMIP 1.4 binary encoding.
  #
  # Each TTLV item:
  #   Tag:    3 bytes (identifies the field)
  #   Type:   1 byte  (data type)
  #   Length: 4 bytes  (value length in bytes)
  #   Value:  variable (padded to 8-byte alignment)
  module Ttlv
    # KMIP data types
    TYPE_STRUCTURE    = 0x01
    TYPE_INTEGER      = 0x02
    TYPE_LONG_INTEGER = 0x03
    TYPE_BIG_INTEGER  = 0x04
    TYPE_ENUMERATION  = 0x05
    TYPE_BOOLEAN      = 0x06
    TYPE_TEXT_STRING   = 0x07
    TYPE_BYTE_STRING   = 0x08
    TYPE_DATE_TIME     = 0x09
    TYPE_INTERVAL      = 0x0A

    module_function

    # Encode a TTLV item to a binary string.
    #
    # @param tag [Integer] 3-byte tag value (e.g., 0x420069)
    # @param type [Integer] 1-byte type value
    # @param value [String] raw value bytes (binary string)
    # @return [String] encoded TTLV bytes
    def encode(tag, type, value)
      value_len = value.bytesize
      padded = ((value_len + 7) / 8) * 8

      # Tag: 3 bytes big-endian + Type: 1 byte + Length: 4 bytes big-endian
      header = [
        (tag >> 16) & 0xFF,
        (tag >> 8) & 0xFF,
        tag & 0xFF,
        type
      ].pack("C4") + [value_len].pack("N")

      # Value + padding
      result = header + value
      result += ("\x00" * (padded - value_len)) if padded > value_len
      result
    end

    # Encode a Structure (type 0x01) containing child TTLV items.
    def encode_structure(tag, children)
      inner = children.join
      encode(tag, TYPE_STRUCTURE, inner)
    end

    # Encode a 32-bit integer.
    def encode_integer(tag, value)
      encode(tag, TYPE_INTEGER, [value].pack("N"))
    end

    # Encode a 64-bit long integer.
    def encode_long_integer(tag, value)
      encode(tag, TYPE_LONG_INTEGER, [value >> 32, value & 0xFFFFFFFF].pack("NN"))
    end

    # Encode an enumeration (32-bit unsigned).
    def encode_enum(tag, value)
      encode(tag, TYPE_ENUMERATION, [value].pack("N"))
    end

    # Encode a boolean.
    def encode_boolean(tag, value)
      val = value ? 1 : 0
      encode(tag, TYPE_BOOLEAN, [0, val].pack("NN"))
    end

    # Encode a text string (UTF-8).
    def encode_text_string(tag, value)
      encode(tag, TYPE_TEXT_STRING, value.encode("UTF-8").b)
    end

    # Encode a byte string (raw bytes).
    def encode_byte_string(tag, value)
      encode(tag, TYPE_BYTE_STRING, value.b)
    end

    # Encode a DateTime (64-bit POSIX timestamp).
    def encode_date_time(tag, value)
      encode(tag, TYPE_DATE_TIME, [value >> 32, value & 0xFFFFFFFF].pack("NN"))
    end

    # Maximum nesting depth for TTLV structures.
    MAX_DECODE_DEPTH = 32

    # Decode a TTLV buffer into a parsed tree.
    #
    # @param buf [String] raw TTLV bytes (binary string)
    # @param offset [Integer] starting offset
    # @param depth [Integer] current recursion depth (internal)
    # @return [Hash] with keys: :tag, :type, :value, :length, :total_length
    def decode(buf, offset = 0, depth = 0)
      raise "TTLV: maximum nesting depth exceeded" if depth > MAX_DECODE_DEPTH
      raise "TTLV buffer too short for header" if buf.bytesize - offset < 8

      bytes = buf.byteslice(offset, 8).unpack("C4N")
      tag = (bytes[0] << 16) | (bytes[1] << 8) | bytes[2]
      type = bytes[3]
      length = bytes[4]
      padded = ((length + 7) / 8) * 8
      total_length = 8 + padded
      value_start = offset + 8

      # Bounds check: ensure declared length fits within buffer.
      if value_start + padded > buf.bytesize
        raise "TTLV: declared length #{length} exceeds buffer (have #{buf.bytesize - value_start} bytes)"
      end

      value = case type
              when TYPE_STRUCTURE
                children = []
                pos = value_start
                end_pos = value_start + length
                while pos < end_pos
                  child = decode(buf, pos, depth + 1)
                  children << child
                  pos += child[:total_length]
                end
                children
              when TYPE_INTEGER
                raw = buf.byteslice(value_start, 4).unpack1("N")
                raw >= 0x80000000 ? raw - 0x100000000 : raw
              when TYPE_LONG_INTEGER
                hi, lo = buf.byteslice(value_start, 8).unpack("NN")
                val = (hi << 32) | lo
                val >= (1 << 63) ? val - (1 << 64) : val
              when TYPE_ENUMERATION
                buf.byteslice(value_start, 4).unpack1("N")
              when TYPE_BOOLEAN
                hi, lo = buf.byteslice(value_start, 8).unpack("NN")
                ((hi << 32) | lo) != 0
              when TYPE_TEXT_STRING
                buf.byteslice(value_start, length).force_encoding("UTF-8")
              when TYPE_BYTE_STRING
                buf.byteslice(value_start, length)
              when TYPE_DATE_TIME
                hi, lo = buf.byteslice(value_start, 8).unpack("NN")
                val = (hi << 32) | lo
                val >= (1 << 63) ? val - (1 << 64) : val
              when TYPE_INTERVAL
                buf.byteslice(value_start, 4).unpack1("N")
              else
                buf.byteslice(value_start, length)
              end

      {
        tag: tag,
        type: type,
        value: value,
        length: length,
        total_length: total_length
      }
    end

    # Find a child item by tag within a decoded structure.
    def find_child(decoded, tag)
      return nil unless decoded[:value].is_a?(Array)

      decoded[:value].find { |c| c[:tag] == tag }
    end

    # Find all children by tag within a decoded structure.
    def find_children(decoded, tag)
      return [] unless decoded[:value].is_a?(Array)

      decoded[:value].select { |c| c[:tag] == tag }
    end
  end
end
