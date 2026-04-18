# frozen_string_literal: true

require "socket"
require "openssl"

module CypheraKmip
  # KMIP client -- connects to any KMIP 1.4 server via mTLS.
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
  #   # key is a binary string of raw key bytes
  #
  #   client.close
  class Client
    # @param host [String] KMIP server hostname
    # @param client_cert [String] path to client certificate PEM file
    # @param client_key [String] path to client private key PEM file
    # @param port [Integer] KMIP server port (default 5696)
    # @param ca_cert [String, nil] path to CA certificate PEM file
    # @param timeout [Integer] connection timeout in seconds (default 10)
    def initialize(host:, client_cert:, client_key:, port: 5696, ca_cert: nil, timeout: 10)
      @host = host
      @port = port
      @timeout = timeout
      @client_cert = client_cert
      @client_key = client_key
      @ca_cert = ca_cert
      @socket = nil
    end

    # Locate keys by name.
    #
    # @param name [String] key name to search for
    # @return [Array<String>] array of unique identifiers
    def locate(name)
      request = Operations.build_locate_request(name)
      response_data = send_request(request)
      response = Operations.parse_response(response_data)
      Operations.parse_locate_payload(response[:payload])[:unique_identifiers]
    end

    # Get key material by unique ID.
    #
    # @param unique_id [String] the unique identifier of the key
    # @return [Hash] with keys: :object_type, :unique_identifier, :key_material
    def get(unique_id)
      request = Operations.build_get_request(unique_id)
      response_data = send_request(request)
      response = Operations.parse_response(response_data)
      Operations.parse_get_payload(response[:payload])
    end

    # Create a new symmetric key on the server.
    #
    # @param name [String] key name
    # @param algorithm [String, nil] algorithm name (e.g., "AES")
    # @param length [Integer] key length in bits (default 256)
    # @return [Hash] with keys: :object_type, :unique_identifier
    def create(name, algorithm = nil, length = 256)
      algo_map = {
        "AES" => Algorithm::AES,
        "DES" => Algorithm::DES,
        "TripleDES" => Algorithm::TRIPLE_DES,
        "RSA" => Algorithm::RSA,
      }
      algo_enum = Algorithm::AES
      if algorithm
        algo_enum = algo_map[algorithm] || algo_map[algorithm.upcase] || Algorithm::AES
      end

      request = Operations.build_create_request(name, algo_enum, length)
      response_data = send_request(request)
      response = Operations.parse_response(response_data)
      Operations.parse_create_payload(response[:payload])
    end

    # Convenience: locate by name + get material in one call.
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
      if @socket
        @socket.close
        @socket = nil
      end
    end

    private

    def send_request(request)
      socket = connect
      socket.write(request)

      # Read TTLV header (8 bytes) to determine total length
      header = recv_exact(socket, 8)
      value_length = header.byteslice(4, 4).unpack1("N")
      body = recv_exact(socket, value_length)
      header + body
    end

    def recv_exact(socket, n)
      data = String.new(encoding: "BINARY")
      while data.bytesize < n
        chunk = socket.read(n - data.bytesize)
        raise "KMIP connection closed unexpectedly" if chunk.nil? || chunk.empty?

        data << chunk
      end
      data
    end

    def connect
      return @socket if @socket

      tcp = TCPSocket.new(@host, @port)
      tcp.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)

      ctx = OpenSSL::SSL::SSLContext.new
      ctx.cert = OpenSSL::X509::Certificate.new(File.read(@client_cert))
      ctx.key = OpenSSL::PKey.read(File.read(@client_key))

      if @ca_cert
        ctx.ca_file = @ca_cert
        ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
      else
        ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
      end

      ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
      ssl.hostname = @host
      ssl.connect

      @socket = ssl
    end
  end
end
