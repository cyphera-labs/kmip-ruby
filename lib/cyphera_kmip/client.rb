# frozen_string_literal: true

require "socket"
require "openssl"

module CypheraKmip
  # KMIP client -- connects to any KMIP 1.4 server via mTLS.
  #
  # Supports all 27 KMIP 1.4 operations.
  #
  # Usage:
  #   client = CypheraKmip::Client.new(
  #     host: "kmip-server.corp.internal",
  #     client_cert: "/path/to/client.pem",
  #     client_key: "/path/to/client-key.pem",
  #     ca_cert: "/path/to/ca.pem",
  #   )
  #
  #   key = client.fetch_key("my-key-name")
  #   client.close
  class Client
    ALGO_MAP = {
      "AES" => Algorithm::AES,
      "DES" => Algorithm::DES,
      "TRIPLEDES" => Algorithm::TRIPLE_DES,
      "3DES" => Algorithm::TRIPLE_DES,
      "RSA" => Algorithm::RSA,
      "DSA" => Algorithm::DSA,
      "ECDSA" => Algorithm::ECDSA,
      "HMACSHA1" => Algorithm::HMAC_SHA1,
      "HMACSHA256" => Algorithm::HMAC_SHA256,
      "HMACSHA384" => Algorithm::HMAC_SHA384,
      "HMACSHA512" => Algorithm::HMAC_SHA512,
    }.freeze

    # Maximum KMIP response size (16MB).
    MAX_RESPONSE_SIZE = 16 * 1024 * 1024

    # @param host [String] KMIP server hostname
    # @param client_cert [String] path to client certificate PEM file
    # @param client_key [String] path to client private key PEM file
    # @param port [Integer] KMIP server port (default 5696)
    # @param ca_cert [String, nil] path to CA certificate PEM file
    # @param timeout [Integer] connection timeout in seconds (default 10)
    # @param insecure_skip_verify [Boolean] DANGER: disables server certificate verification (default false)
    # @param server_cert_fingerprint [String, nil] SHA-256 hex fingerprint for certificate pinning
    def initialize(host:, client_cert:, client_key:, port: 5696, ca_cert: nil, timeout: 10, insecure_skip_verify: false, server_cert_fingerprint: nil)
      @host = host
      @port = port
      @timeout = timeout
      @client_cert = client_cert
      @client_key = client_key
      @ca_cert = ca_cert
      @insecure_skip_verify = insecure_skip_verify
      @server_cert_fingerprint = server_cert_fingerprint
      @socket = nil
      @mutex = Mutex.new

      if @insecure_skip_verify
        warn "KmipClient: insecure_skip_verify: true disables TLS certificate verification. NEVER use in production."
      end
    end

    # Resolve an algorithm name string to its KMIP enum value.
    #
    # @raise [ArgumentError] for unknown algorithm names.
    def self.resolve_algorithm(name)
      ALGO_MAP.fetch(name.to_s.upcase) { raise ArgumentError, "Unknown KMIP algorithm: #{name}" }
    end

    # -------------------------------------------------------------------------
    # 1. Create -- create a new symmetric key on the server.
    # -------------------------------------------------------------------------

    def create(name, algorithm = nil, length = 256)
      algo_enum = Algorithm::AES
      if algorithm.is_a?(String)
        algo_enum = self.class.resolve_algorithm(algorithm)
        algo_enum = Algorithm::AES if algo_enum.zero?
      elsif algorithm.is_a?(Integer)
        algo_enum = algorithm
      end

      request = Operations.build_create_request(name, algo_enum, length)
      response_data = send_request(request)
      response = Operations.parse_response(response_data)
      Operations.parse_create_payload(response[:payload])
    end

    # -------------------------------------------------------------------------
    # 2. CreateKeyPair -- create a new asymmetric key pair.
    # -------------------------------------------------------------------------

    def create_key_pair(name, algorithm, length)
      algo_enum = algorithm.is_a?(String) ? self.class.resolve_algorithm(algorithm) : algorithm
      request = Operations.build_create_key_pair_request(name, algo_enum, length)
      response_data = send_request(request)
      response = Operations.parse_response(response_data)
      Operations.parse_create_key_pair_payload(response[:payload])
    end

    # -------------------------------------------------------------------------
    # 3. Register -- register existing key material on the server.
    # -------------------------------------------------------------------------

    def register(object_type, material, name, algorithm, length)
      algo_enum = algorithm.is_a?(String) ? self.class.resolve_algorithm(algorithm) : algorithm
      request = Operations.build_register_request(object_type, material, name, algo_enum, length)
      response_data = send_request(request)
      response = Operations.parse_response(response_data)
      Operations.parse_create_payload(response[:payload])
    end

    # -------------------------------------------------------------------------
    # 4. ReKey -- re-key an existing key.
    # -------------------------------------------------------------------------

    def re_key(unique_id)
      request = Operations.build_re_key_request(unique_id)
      response_data = send_request(request)
      response = Operations.parse_response(response_data)
      Operations.parse_re_key_payload(response[:payload])
    end

    # -------------------------------------------------------------------------
    # 5. DeriveKey -- derive a new key from an existing key.
    # -------------------------------------------------------------------------

    def derive_key(unique_id, derivation_data, name, length, derivation_method: 0x00000004)
      request = Operations.build_derive_key_request(unique_id, derivation_data, name, length, derivation_method: derivation_method)
      response_data = send_request(request)
      response = Operations.parse_response(response_data)
      Operations.parse_derive_key_payload(response[:payload])
    end

    # -------------------------------------------------------------------------
    # 6. Locate -- find keys by name.
    # -------------------------------------------------------------------------

    def locate(name)
      request = Operations.build_locate_request(name)
      response_data = send_request(request)
      response = Operations.parse_response(response_data)
      Operations.parse_locate_payload(response[:payload])[:unique_identifiers]
    end

    # -------------------------------------------------------------------------
    # 7. Check -- check the status of a managed object.
    # -------------------------------------------------------------------------

    def check(unique_id)
      request = Operations.build_check_request(unique_id)
      response_data = send_request(request)
      response = Operations.parse_response(response_data)
      Operations.parse_check_payload(response[:payload])
    end

    # -------------------------------------------------------------------------
    # 8. Get -- fetch key material by unique ID.
    # -------------------------------------------------------------------------

    def get(unique_id)
      request = Operations.build_get_request(unique_id)
      response_data = send_request(request)
      response = Operations.parse_response(response_data)
      Operations.parse_get_payload(response[:payload])
    end

    # -------------------------------------------------------------------------
    # 9. GetAttributes -- fetch all attributes of a managed object.
    # -------------------------------------------------------------------------

    def get_attributes(unique_id)
      request = Operations.build_get_attributes_request(unique_id)
      response_data = send_request(request)
      response = Operations.parse_response(response_data)
      Operations.parse_get_payload(response[:payload])
    end

    # -------------------------------------------------------------------------
    # 10. GetAttributeList -- fetch the list of attribute names.
    # -------------------------------------------------------------------------

    def get_attribute_list(unique_id)
      request = Operations.build_get_attribute_list_request(unique_id)
      response_data = send_request(request)
      response = Operations.parse_response(response_data)
      return [] if response[:payload].nil?

      attrs = Ttlv.find_children(response[:payload], Tag::ATTRIBUTE_NAME)
      attrs.map { |a| a[:value] }
    end

    # -------------------------------------------------------------------------
    # 11. AddAttribute -- add an attribute to a managed object.
    # -------------------------------------------------------------------------

    def add_attribute(unique_id, name, value)
      request = Operations.build_add_attribute_request(unique_id, name, value)
      response_data = send_request(request)
      Operations.parse_response(response_data)
      nil
    end

    # -------------------------------------------------------------------------
    # 12. ModifyAttribute -- modify an attribute of a managed object.
    # -------------------------------------------------------------------------

    def modify_attribute(unique_id, name, value)
      request = Operations.build_modify_attribute_request(unique_id, name, value)
      response_data = send_request(request)
      Operations.parse_response(response_data)
      nil
    end

    # -------------------------------------------------------------------------
    # 13. DeleteAttribute -- delete an attribute from a managed object.
    # -------------------------------------------------------------------------

    def delete_attribute(unique_id, name)
      request = Operations.build_delete_attribute_request(unique_id, name)
      response_data = send_request(request)
      Operations.parse_response(response_data)
      nil
    end

    # -------------------------------------------------------------------------
    # 14. ObtainLease -- obtain a lease for a managed object.
    # -------------------------------------------------------------------------

    def obtain_lease(unique_id)
      request = Operations.build_obtain_lease_request(unique_id)
      response_data = send_request(request)
      response = Operations.parse_response(response_data)
      return 0 if response[:payload].nil?

      lease = Ttlv.find_child(response[:payload], Tag::LEASE_TIME)
      lease ? lease[:value] : 0
    end

    # -------------------------------------------------------------------------
    # 15. Activate -- set a key's state to Active.
    # -------------------------------------------------------------------------

    def activate(unique_id)
      request = Operations.build_activate_request(unique_id)
      response_data = send_request(request)
      Operations.parse_response(response_data)
      nil
    end

    # -------------------------------------------------------------------------
    # 16. Revoke -- revoke a managed object with a reason code.
    # -------------------------------------------------------------------------

    def revoke(unique_id, reason)
      request = Operations.build_revoke_request(unique_id, reason)
      response_data = send_request(request)
      Operations.parse_response(response_data)
      nil
    end

    # -------------------------------------------------------------------------
    # 17. Destroy -- destroy a key by unique ID.
    # -------------------------------------------------------------------------

    def destroy(unique_id)
      request = Operations.build_destroy_request(unique_id)
      response_data = send_request(request)
      Operations.parse_response(response_data)
      nil
    end

    # -------------------------------------------------------------------------
    # 18. Archive -- archive a managed object.
    # -------------------------------------------------------------------------

    def archive(unique_id)
      request = Operations.build_archive_request(unique_id)
      response_data = send_request(request)
      Operations.parse_response(response_data)
      nil
    end

    # -------------------------------------------------------------------------
    # 19. Recover -- recover an archived managed object.
    # -------------------------------------------------------------------------

    def recover(unique_id)
      request = Operations.build_recover_request(unique_id)
      response_data = send_request(request)
      Operations.parse_response(response_data)
      nil
    end

    # -------------------------------------------------------------------------
    # 20. Query -- query the server for supported operations and object types.
    # -------------------------------------------------------------------------

    def query
      request = Operations.build_query_request
      response_data = send_request(request)
      response = Operations.parse_response(response_data)
      Operations.parse_query_payload(response[:payload])
    end

    # -------------------------------------------------------------------------
    # 21. Poll -- poll the server.
    # -------------------------------------------------------------------------

    def poll
      request = Operations.build_poll_request
      response_data = send_request(request)
      Operations.parse_response(response_data)
      nil
    end

    # -------------------------------------------------------------------------
    # 22. DiscoverVersions -- discover supported KMIP versions.
    # -------------------------------------------------------------------------

    def discover_versions
      request = Operations.build_discover_versions_request
      response_data = send_request(request)
      response = Operations.parse_response(response_data)
      Operations.parse_discover_versions_payload(response[:payload])
    end

    # -------------------------------------------------------------------------
    # 23. Encrypt -- encrypt data using a managed key.
    # -------------------------------------------------------------------------

    def encrypt(unique_id, data)
      request = Operations.build_encrypt_request(unique_id, data)
      response_data = send_request(request)
      response = Operations.parse_response(response_data)
      Operations.parse_encrypt_payload(response[:payload])
    end

    # -------------------------------------------------------------------------
    # 24. Decrypt -- decrypt data using a managed key.
    # -------------------------------------------------------------------------

    def decrypt(unique_id, data, nonce = nil)
      request = Operations.build_decrypt_request(unique_id, data, nonce)
      response_data = send_request(request)
      response = Operations.parse_response(response_data)
      Operations.parse_decrypt_payload(response[:payload])
    end

    # -------------------------------------------------------------------------
    # 25. Sign -- sign data using a managed key.
    # -------------------------------------------------------------------------

    def sign(unique_id, data)
      request = Operations.build_sign_request(unique_id, data)
      response_data = send_request(request)
      response = Operations.parse_response(response_data)
      Operations.parse_sign_payload(response[:payload])
    end

    # -------------------------------------------------------------------------
    # 26. SignatureVerify -- verify a signature using a managed key.
    # -------------------------------------------------------------------------

    def signature_verify(unique_id, data, signature)
      request = Operations.build_signature_verify_request(unique_id, data, signature)
      response_data = send_request(request)
      response = Operations.parse_response(response_data)
      Operations.parse_signature_verify_payload(response[:payload])
    end

    # -------------------------------------------------------------------------
    # 27. MAC -- compute a MAC using a managed key.
    # -------------------------------------------------------------------------

    def mac(unique_id, data)
      request = Operations.build_mac_request(unique_id, data)
      response_data = send_request(request)
      response = Operations.parse_response(response_data)
      Operations.parse_mac_payload(response[:payload])
    end

    # -------------------------------------------------------------------------
    # Convenience methods
    # -------------------------------------------------------------------------

    # Locate by name + get material in one call.
    #
    # @param name [String] key name
    # @return [String] raw key bytes (binary string)
    def fetch_key(name)
      ids = locate(name)
      raise "KMIP: no key found with name \"#{name}\"" if ids.empty?

      result = get(ids[0])
      unless result[:key_material]
        raise "KMIP: key \"#{name}\" (#{ids[0]}) has no extractable material"
      end

      result[:key_material]
    end

    # Close the TLS connection.
    def close
      @mutex.synchronize do
        if @socket
          @socket.close
          @socket = nil
        end
      end
    end

    private

    def send_request(request)
      socket = connect
      begin
        socket.write(request)
      rescue IOError, SystemCallError
        @mutex.synchronize { @socket = nil }
        raise
      end

      # Read TTLV header (8 bytes) to determine total length
      begin
        header = recv_exact(socket, 8)
      rescue IOError, SystemCallError
        @mutex.synchronize { @socket = nil }
        raise
      end

      value_length = header.byteslice(4, 4).unpack1("N")

      # Validate response size before allocating.
      if value_length > MAX_RESPONSE_SIZE
        @mutex.synchronize { @socket = nil }
        raise "KMIP: response too large (#{value_length} bytes, max #{MAX_RESPONSE_SIZE})"
      end

      begin
        body = recv_exact(socket, value_length)
      rescue IOError, SystemCallError
        @mutex.synchronize { @socket = nil }
        raise
      end

      header + body
    end

    def recv_exact(socket, n)
      data = String.new(encoding: "BINARY")
      while data.bytesize < n
        unless IO.select([socket], nil, nil, @timeout)
          raise "KMIP: read timed out after #{@timeout}s"
        end
        chunk = socket.read(n - data.bytesize)
        raise "KMIP connection closed unexpectedly" if chunk.nil? || chunk.empty?

        data << chunk
      end
      data
    end

    def connect
      @mutex.synchronize do
        return @socket if @socket && !@socket.closed?

        # Non-blocking connect with timeout
        addr = Socket.sockaddr_in(@port, @host)
        tcp = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM)
        tcp.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
        begin
          tcp.connect_nonblock(addr)
        rescue IO::WaitWritable
          unless IO.select(nil, [tcp], nil, @timeout)
            tcp.close
            raise "KMIP connection timed out after #{@timeout}s"
          end
          begin
            tcp.connect_nonblock(addr)
          rescue Errno::EISCONN
            # Already connected — expected on retry
          end
        end

        ctx = OpenSSL::SSL::SSLContext.new
        ctx.min_version = OpenSSL::SSL::TLS1_2_VERSION
        ctx.cert = OpenSSL::X509::Certificate.new(File.read(@client_cert))
        ctx.key = OpenSSL::PKey.read(File.read(@client_key))

        if @ca_cert
          ctx.ca_file = @ca_cert
        else
          ctx.cert_store = OpenSSL::X509::Store.new
          ctx.cert_store.set_default_paths
        end

        if @insecure_skip_verify
          ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
        else
          ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
        end

        if @server_cert_fingerprint
          ctx.verify_callback = proc do |preverify_ok, store_ctx|
            return false unless preverify_ok || @insecure_skip_verify

            cert = store_ctx.current_cert
            if store_ctx.chain&.first == cert
              fingerprint = OpenSSL::Digest::SHA256.hexdigest(cert.to_der)
              return fingerprint.downcase == @server_cert_fingerprint.downcase
            end
            true
          end
        end

        ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
        ssl.hostname = @host
        ssl.connect

        @socket = ssl
      end
    end
  end
end
