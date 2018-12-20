module Aliquot
  ##
  # A Payment represents a single payment using Google Pay.
  # It is used to verify/decrypt the supplied token by using the shared secret,
  # thus avoiding having knowledge of merchant primary keys.
  class Payment
    ##
    # Parameters:
    # token_string::  Google Pay token (JSON string)
    # shared_secret:: Base64 encoded shared secret
    # merchant_id::   Google Pay merchant ID ("merchant:<SOMETHING>")
    # logger::        The logger to use. Default: Logger.new($stdout)
    # signing_keys::  Formatted list of signing keys used to sign token contents.
    #                 Otherwise a thread continuously updating google signing
    #                 keys will be started.
    def initialize(token_string, shared_secret, merchant_id,
                   logger: Logger.new($stdout),
                   signing_keys: ENV['GOOGLE_SIGNING_KEYS'])
      Aliquot.start_key_updater(logger) if $key_updater_thread.nil? && signing_keys.nil?

      validation = Aliquot::Validator::Token.new(JSON.parse(token_string))
      validation.validate

      @token = validation.output

      @shared_secret = shared_secret
      @merchant_id   = merchant_id
      @signing_keys  = signing_keys
    end

    ##
    # Validate and decrypt the token.
    def process
      unless valid_protocol_version?
        raise Error, 'only ECv1 protocolVersion is supported'
      end

      raise InvalidSignatureError unless valid_signature?

      validator = Aliquot::Validator::SignedMessage.new(JSON.parse(@token[:signedMessage]))
      validator.validate
      signed_message = validator.output

      aes_key, mac_key = derive_keys(signed_message[:ephemeralPublicKey], @shared_secret, 'Google')

      unless self.class.valid_mac?(mac_key, signed_message[:encryptedMessage], signed_message[:tag])
        raise InvalidMacError
      end

      @message = JSON.parse(self.class.decrypt(aes_key, signed_message[:encryptedMessage]))

      message_validator = Aliquot::Validator::EncryptedMessageValidator.new(@message)
      message_validator.validate

      # Output is hashed with symbolized keys.
      @message = message_validator.output

      raise ExpiredException if expired?

      @message
    end

    def protocol_version
      @token[:protocolVersion]
    end

    def valid_protocol_version?
      protocol_version == 'ECv1'
    end

    ##
    # Check if the token is expired, according to the messageExpiration included
    # in the token.
    def expired?
      @message[:messageExpiration].to_f / 1000.0 <= Time.now.to_f
    end

    def valid_signature?
      signed_string = ['Google', @merchant_id, protocol_version, @token[:signedMessage]].map do |str|
        [str.length].pack('V') + str
      end.join

      keys = JSON.parse(signing_keys)['keys']
      # Check if signature was performed with any possible key.
      keys.map do |key|
        next if key['protocolVersion'] != protocol_version

        ec = OpenSSL::PKey::EC.new(Base64.strict_decode64(key['keyValue']))
        ec.verify(OpenSSL::Digest::SHA256.new, Base64.strict_decode64(@token[:signature]), signed_string)
      end.any?
    end

    def self.decrypt(key, encrypted)
      c = OpenSSL::Cipher::AES128.new(:CTR)
      c.key = key
      c.decrypt

      c.update(Base64.strict_decode64(encrypted)) + c.final
    end

    def self.valid_mac?(mac_key, data, tag)
      digest = OpenSSL::Digest::SHA256.new
      mac = OpenSSL::HMAC.digest(digest, mac_key, Base64.strict_decode64(data))

      compare(Base64.strict_encode64(mac), tag)
    end

    def self.compare(a, b)
      return false unless a.length == b.length

      diffs = 0

      ys = b.unpack('C*')

      a.each_byte do |x|
        diffs |= x ^ ys.shift
      end

      diffs.zero?
    end

    private

    # Keys are derived according to the Google Pay specification.
    def derive_keys(ephemeral_public_key, shared_secret, info)
      input_keying_material = Base64.strict_decode64(ephemeral_public_key) + Base64.strict_decode64(shared_secret)

      if OpenSSL.const_defined?(:KDF) && OpenSSL::KDF.respond_to?(:hkdf)
        h = OpenSSL::Digest::SHA256.new
        key_bytes = OpenSSL::KDF.hkdf(input_keying_material, hash: h, salt: '', length: 32, info: info)
      else
        key_bytes = HKDF.new(input_keying_material, algorithm: 'SHA256', info: info).next_bytes(32)
      end

      [key_bytes[0..15], key_bytes[16..32]]
    end

    def signing_keys
      # Prefer static signing keys, otherwise fetch from updating thread.
      @signing_keys || $key_updater_thread.thread_variable_get('keys')
    end
  end
end
