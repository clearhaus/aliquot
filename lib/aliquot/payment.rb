require 'json'
require 'base64'
require 'hkdf'
require 'openssl'

require 'aliquot/error'
require 'aliquot/validator'

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
    # signing_keys::  Signing keys fetched from Google
    def initialize(token_string, shared_secret, merchant_id,
                   signing_keys: ENV['GOOGLE_SIGNING_KEYS'])

      begin
        validation = Aliquot::Validator::Token.new(JSON.parse(token_string))
        validation.validate
      rescue JSON::JSONError => e
        raise InputError, "token JSON invalid, #{e.message}"
      end

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

      check_shared_secret

      raise InvalidSignatureError unless valid_signature?

      validator = Aliquot::Validator::SignedMessage.new(JSON.parse(@token[:signedMessage]))
      validator.validate
      signed_message = validator.output

      begin
        aes_key, mac_key = derive_keys(signed_message[:ephemeralPublicKey], @shared_secret, 'Google')
      rescue => e
        raise KeyDerivationError, "unable to derive keys, #{e.message}"
      end

      unless self.class.valid_mac?(mac_key, signed_message[:encryptedMessage], signed_message[:tag])
        raise InvalidMacError
      end

      begin
        @message = JSON.parse(self.class.decrypt(aes_key, signed_message[:encryptedMessage]))
      rescue JSON::JSONError => e
        raise InputError, "encryptedMessage JSON invalid, #{e.message}"
      rescue => e
        raise DecryptionError, "decryption failed, #{e.message}"
      end

      message_validator = Aliquot::Validator::EncryptedMessageValidator.new(@message)
      message_validator.validate

      # Output is hashed with symbolized keys.
      @message = message_validator.output

      raise TokenExpiredError if expired?

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

      keys = JSON.parse(@signing_keys)['keys']
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

    def check_shared_secret
      begin
        decoded = Base64.strict_decode64(@shared_secret)
      rescue
        raise InvalidSharedSecretError, 'shared_secret must be base64'
      end

      raise InvalidSharedSecretError, 'shared_secret must be 32 bytes when base64 decoded' unless decoded.length == 32
    end
  end
end
