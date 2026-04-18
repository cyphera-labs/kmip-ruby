# frozen_string_literal: true

module CypheraKmip
  # KMIP 1.4 tag, type, and enum constants.
  # Only the subset needed for Locate, Get, Create operations.
  #
  # Reference: OASIS KMIP Specification v1.4
  # https://docs.oasis-open.org/kmip/spec/v1.4/kmip-spec-v1.4.html
  module Tag
    # Message structure
    REQUEST_MESSAGE        = 0x420078
    RESPONSE_MESSAGE       = 0x42007B
    REQUEST_HEADER         = 0x420077
    RESPONSE_HEADER        = 0x42007A
    PROTOCOL_VERSION       = 0x420069
    PROTOCOL_VERSION_MAJOR = 0x42006A
    PROTOCOL_VERSION_MINOR = 0x42006B
    BATCH_COUNT            = 0x42000D
    BATCH_ITEM             = 0x42000F
    OPERATION              = 0x42005C
    REQUEST_PAYLOAD        = 0x420079
    RESPONSE_PAYLOAD       = 0x42007C
    RESULT_STATUS          = 0x42007F
    RESULT_REASON          = 0x420080
    RESULT_MESSAGE         = 0x420081

    # Object identification
    UNIQUE_IDENTIFIER = 0x420094
    OBJECT_TYPE       = 0x420057

    # Naming
    NAME       = 0x420053
    NAME_VALUE = 0x420055
    NAME_TYPE  = 0x420054

    # Attributes (KMIP 1.x style)
    ATTRIBUTE       = 0x420008
    ATTRIBUTE_NAME  = 0x42000A
    ATTRIBUTE_VALUE = 0x42000B

    # Key structure
    SYMMETRIC_KEY   = 0x42008F
    KEY_BLOCK       = 0x420040
    KEY_FORMAT_TYPE = 0x420042
    KEY_VALUE       = 0x420045
    KEY_MATERIAL    = 0x420043

    # Crypto attributes
    CRYPTOGRAPHIC_ALGORITHM  = 0x420028
    CRYPTOGRAPHIC_LENGTH     = 0x42002A
    CRYPTOGRAPHIC_USAGE_MASK = 0x42002C

    # Template
    TEMPLATE_ATTRIBUTE = 0x420091
  end

  module Operation
    CREATE   = 0x00000001
    GET      = 0x0000000A
    LOCATE   = 0x00000008
    ACTIVATE = 0x00000012
    DESTROY  = 0x00000014
    CHECK    = 0x00000009
  end

  module ObjectType
    CERTIFICATE   = 0x00000001
    SYMMETRIC_KEY = 0x00000002
    PUBLIC_KEY    = 0x00000003
    PRIVATE_KEY   = 0x00000004
    SPLIT_KEY     = 0x00000005
    TEMPLATE      = 0x00000006
    SECRET_DATA   = 0x00000007
    OPAQUE_DATA   = 0x00000008
  end

  module ResultStatus
    SUCCESS           = 0x00000000
    OPERATION_FAILED  = 0x00000001
    OPERATION_PENDING = 0x00000002
    OPERATION_UNDONE  = 0x00000003
  end

  module KeyFormatType
    RAW                   = 0x00000001
    OPAQUE                = 0x00000002
    PKCS1                 = 0x00000003
    PKCS8                 = 0x00000004
    X509                  = 0x00000005
    EC_PRIVATE_KEY        = 0x00000006
    TRANSPARENT_SYMMETRIC = 0x00000007
  end

  module Algorithm
    DES         = 0x00000001
    TRIPLE_DES  = 0x00000002
    AES         = 0x00000003
    RSA         = 0x00000004
    DSA         = 0x00000005
    ECDSA       = 0x00000006
    HMAC_SHA1   = 0x00000007
    HMAC_SHA256 = 0x00000008
    HMAC_SHA384 = 0x00000009
    HMAC_SHA512 = 0x0000000A
  end

  module NameType
    UNINTERPRETED_TEXT_STRING = 0x00000001
    URI                      = 0x00000002
  end

  module UsageMask
    SIGN          = 0x00000001
    VERIFY        = 0x00000002
    ENCRYPT       = 0x00000004
    DECRYPT       = 0x00000008
    WRAP_KEY      = 0x00000010
    UNWRAP_KEY    = 0x00000020
    EXPORT        = 0x00000040
    DERIVE_KEY    = 0x00000100
    KEY_AGREEMENT = 0x00000800
  end
end
