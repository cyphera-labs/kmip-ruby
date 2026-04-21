# frozen_string_literal: true

module CypheraKmip
  # Structured KMIP exception carrying result status and reason codes.
  #
  # Extends RuntimeError so existing rescue blocks continue to work.
  class KmipError < RuntimeError
    attr_reader :result_status, :result_reason

    def initialize(msg, result_status: 0, result_reason: 0)
      super(msg)
      @result_status = result_status
      @result_reason = result_reason
    end
  end
end
