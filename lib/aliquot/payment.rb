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
  # thus avoiding having knowledge of any private keys involved.
  class Payment
    SUPPORTED_PROTOCOL_VERSIONS = %w[ECv1 ECv2].freeze
    ##
    # Parameters:
    # token_string::  Google Pay token (JSON string)
    # shared_secret:: Base64 encoded shared secret
    # recipient_id::   Google Pay recipient ID
    # signing_keys::  Signing keys fetched from Google
    def initialize(token_string, shared_secret, recipient_id,
                   signing_keys: ENV['GOOGLE_SIGNING_KEYS'])

      begin
        validation = Aliquot::Validator::Token.new(JSON.parse(token_string))
        validation.validate
      rescue JSON::JSONError => e
        raise InputError, "token JSON is invalid, #{e.message}"
      end

      @token = validation.output

      @shared_secret = shared_secret
      @recipient_id   = recipient_id
      @signing_keys  = signing_keys
    end

    ##
    # Validate and decrypt the token.
    def process
      unless valid_protocol_version?
        raise Error, "supported protocol versions are #{SUPPORTED_PROTOCOL_VERSIONS.join(', ')}"
      end

      @recipient_id = validate_recipient_id

      check_shared_secret

      if protocol_version == 'ECv2'
        @intermediate_key = validate_intermediate_key
        raise InvalidSignatureError, 'intermediate certificate is expired' if intermediate_key_expired?
      end

      check_signature

      @signed_message = validate_signed_message

      begin
        aes_key, mac_key = derive_keys(@signed_message[:ephemeralPublicKey], @shared_secret, 'Google')
      rescue => e
        raise KeyDerivationError, "cannot derive keys, #{e.message}"
      end

      raise InvalidMacError, 'MAC does not match' unless valid_mac?(mac_key)

      begin
        @message = JSON.parse(decrypt(aes_key, @signed_message[:encryptedMessage]))
        @message["paymentMethodDetails"].merge!(
          'threedsCryptogram' => @message["paymentMethodDetails"]
          .delete('3dsCryptogram')) if @message["paymentMethodDetails"]['3dsCryptogram']
      rescue JSON::JSONError => e
        raise InputError, "encryptedMessage JSON is invalid, #{e.message}"
      rescue => e
        raise DecryptionError, "decryption failed, #{e.message}"
      end


      @message = validate_message

      raise TokenExpiredError, 'token is expired' if expired?

      @message
    end

    def protocol_version
      @token[:protocolVersion]
    end

    def valid_protocol_version?
      SUPPORTED_PROTOCOL_VERSIONS.include?(protocol_version)
    end

    def validate_intermediate_key
      # Valid JSON as it has been checked by Token Validator.
      intermediate_key = JSON.parse(@token[:intermediateSigningKey][:signedKey])

      validator = Aliquot::Validator::SignedKeyValidator.new(intermediate_key)
      validator.validate

      validator.output
    end

    def intermediate_key_expired?
      cur_millis = (Time.now.to_f * 1000).round
      @intermediate_key[:keyExpiration].to_i < cur_millis
    end

    def validate_recipient_id
      raise InvalidRecipientIDError, 'recipient_id must be alphanumeric and punctuation' unless /\A[[:graph:]]+\z/ =~ @recipient_id

      @recipient_id
    end

    def check_shared_secret
      begin
        decoded = Base64.strict_decode64(@shared_secret)
      rescue
        raise InvalidSharedSecretError, 'shared_secret must be base64'
      end

      raise InvalidSharedSecretError, 'shared_secret must be 32 bytes when base64 decoded' unless decoded.length == 32
    end

    def check_signature
      signed_string_message = ['Google', @recipient_id, protocol_version, @token[:signedMessage]].map do |str|
        [str.length].pack('V') + str
      end.join
      message_signature = Base64.strict_decode64(@token[:signature])

      root_signing_keys = root_keys

      case protocol_version
      when 'ECv1'
        # Check if signature was performed directly with any possible key.
        success =
          root_signing_keys.map do |key|
            key.verify(new_digest, message_signature, signed_string_message)
          end.any?

        raise InvalidSignatureError, 'signature of signedMessage does not match' unless success
      when 'ECv2'
        signed_key_signature = ['Google', 'ECv2', @token[:intermediateSigningKey][:signedKey]].map do |str|
          [str.length].pack('V') + str
        end.join

        # Check that the intermediate key signed the message
        pkey = OpenSSL::PKey::EC.new(Base64.strict_decode64(@intermediate_key[:keyValue]))
        raise InvalidSignatureError, 'signature of signedMessage does not match' unless pkey.verify(new_digest, message_signature, signed_string_message)

        intermediate_signatures = @token[:intermediateSigningKey][:signatures]

        # Check that a root signing key signed the intermediate
        success = valid_intermediate_key_signatures?(
          root_signing_keys,
          intermediate_signatures,
          signed_key_signature
        )

        raise InvalidSignatureError, 'no valid signature of intermediate key' unless success
      end
    rescue OpenSSL::PKey::PKeyError => e
      # Catches problems with verifying signature. Can be caused by signature
      # being valid ASN1 but having invalid structure.
      raise InvalidSignatureError, "error verifying signature, #{e.message}"
    end

    def root_keys
      root_signing_keys = JSON.parse(@signing_keys)['keys'].select do |key|
        key['protocolVersion'] == protocol_version
      end

      root_signing_keys.map! do |key|
        OpenSSL::PKey::EC.new(Base64.strict_decode64(key['keyValue']))
      end
    end

    def valid_intermediate_key_signatures?(signing_keys, signatures, signed)
      signing_keys.product(signatures).each do |key, sig|
        return true if key.verify(new_digest, Base64.strict_decode64(sig), signed)
      end
      false
    end

    def validate_signed_message
      signed_message = @token[:signedMessage]
      validator = Aliquot::Validator::SignedMessage.new(JSON.parse(signed_message))
      validator.validate
      validator.output
    end

    # Keys are derived according to the Google Pay specification.
    def derive_keys(ephemeral_public_key, shared_secret, info)
      input_keying_material = Base64.strict_decode64(ephemeral_public_key) + Base64.strict_decode64(shared_secret)

      key_len = new_cipher.key_len

      key_bytes = if OpenSSL.const_defined?(:KDF) && OpenSSL::KDF.respond_to?(:hkdf)
                    OpenSSL::KDF.hkdf(input_keying_material, hash: new_digest, salt: '', length: 2 * key_len, info: info)
                  else
                    HKDF.new(input_keying_material, algorithm: 'SHA256', info: info).next_bytes(2 * key_len)
                  end

      [key_bytes[0..key_len - 1], key_bytes[key_len..2 * key_len]]
    end

    def valid_mac?(mac_key)
      data = Base64.strict_decode64(@signed_message[:encryptedMessage])
      tag = @signed_message[:tag]
      mac = OpenSSL::HMAC.digest(new_digest, mac_key, data)

      compare(Base64.strict_encode64(mac), tag)
    end

    def decrypt(key, encrypted)
      c = new_cipher
      c.decrypt
      c.key = key

      c.update(Base64.strict_decode64(encrypted)) + c.final
    end

    def validate_message
      validator = Aliquot::Validator::EncryptedMessageValidator.new(@message)
      validator.validate

      # Output is hashed with symbolized keys.
      message_hash = validator.output

      payment_method_details_message = message_hash[:paymentMethodDetails]
      message_details_validator =
        if message_hash[:paymentMethod] == 'TOKENIZED_CARD' ||
           message_hash[:paymentMethodDetails]['authMethod'] == 'CRYPTOGRAM_3DS'
          Aliquot::Validator::PaymentMethodDetailsValidator.new(payment_method_details_message, protocol_version, true)
        else
          Aliquot::Validator::PaymentMethodDetailsValidator.new(payment_method_details_message, protocol_version, false)
        end
      message_details_validator.validate
      message_hash[:paymentMethodDetails] = message_details_validator.output

      message_hash
    end

    ##
    # Check if the token is expired, according to the messageExpiration included
    # in the token.
    def expired?
      @message[:messageExpiration].to_f / 1000.0 <= Time.now.to_f
    end

    def new_cipher
      case protocol_version
      when 'ECv1'
        OpenSSL::Cipher::AES128.new(:CTR)
      when 'ECv2'
        OpenSSL::Cipher::AES256.new(:CTR)
      end
    end

    def new_digest
      OpenSSL::Digest::SHA256.new
    end

    def compare(a, b)
      return false unless a.length == b.length

      diffs = 0

      ys = b.unpack('C*')

      a.each_byte do |x|
        diffs |= x ^ ys.shift
      end

      diffs.zero?
    end
  end
end
