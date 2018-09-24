require 'json'
require 'base64'
require 'pry'
require 'hkdf'

require 'aliquot/google_key_updater'
require 'aliquot/validator'

module Aliquot
  class Error < StandardError; end
  class ExpiredException < Error; end
  class InvalidSignatureError < Error; end
  class InvalidMacError < Error; end

  # Constant-time comparison function
  def self.compare(a, b)
    err = 0

    y = b.unpack('C*')

    a.each_byte do |x|
      err |= x ^ y.shift
    end

    err.zero?
  end

  class Payment
    # Google Key updater.
    @@gku = nil

    # Parameters:
    # token_string::  Google Pay token
    # shared_secret:: Base64 encoded shared secret
    # merchant_id::   Google Pay merchant ID
    # signing_keys::  Formatted list of signing keys used to sign token contents.
    def initialize(token_string, shared_secret, merchant_id, signing_keys)
      @signing_keys = signing_keys
      # Start the Google Key Updater thread if we haven't.
      # A mutex should be added here to avoid multiple creations
      #if @@gku.nil?
      #  # Provide the initial keys to avoid race issues.
      #  #GoogleKeyUpdater.instance.keys = GoogleKeyUpdater.update_keys
      #  GoogleKeyUpdater.update_keys
      #  @@gku = Thread.new { GoogleKeyUpdater.updater }
      #end

      @shared_secret = shared_secret
      @merchant_id = merchant_id
      @token_string = token_string
    end

    def process
      @token = JSON.parse(@token_string)

      validate(Aliquot::Validator::Token, @token)

      raise InvalidSignatureError unless valid_signature?(@token['signedMessage'],
                                                          @token['signature'])

      @signed_message = JSON.parse(@token['signedMessage'])
      validate(Aliquot::Validator::SignedMessage, @signed_message)

      aes_key, mac_key = derive_keys(@signed_message['ephemeralPublicKey'],
                                     @shared_secret,
                                     'Google')

      raise InvalidMacError unless valid_mac?(mac_key,
                                              @signed_message['encryptedMessage'],
                                              @signed_message['tag'])

      @message = decrypt(aes_key, @signed_message['encryptedMessage'])

      validate(Aliquot::Validator::EncryptedMessageValidator, @message)

      raise ExpiredException if expired?

      @message
    end

    def expired?
      @message['messageExpiration'].to_f / 1000.0 <= Time.now.to_f
    end

    private

    def validate(klass, data)
      validator = klass.new(data)
      validator.validate
    end

    def derive_keys(ephemeral_public_key, shared_secret, info)
      ikm = Base64.strict_decode64(ephemeral_public_key) +
            Base64.strict_decode64(shared_secret)
      hbytes = HKDF.new(ikm, algorithm: 'SHA256', info: info).next_bytes(32)

      [hbytes[0..15], hbytes[16..32]]
    end

    def decrypt(key, encrypted)
      c = OpenSSL::Cipher::AES128.new(:CTR)
      c.key = key
      c.decrypt
      plain = c.update(Base64.strict_decode64(encrypted)) + c.final
      JSON.parse(plain)
    end

    def valid_signature?(message, signature)
      # Genereate the string that was signed.
      signed_string = ['Google', @merchant_id, 'ECv1', message].map do |str|
        [str.length].pack('V') + str
      end.join

      keys = JSON.parse(@signing_keys)['keys']
      # Check if signature was performed with any possible signature.
      keys.map do |e|
        next if e['protocolVersion'] != 'ECv1'

        ec = OpenSSL::PKey::EC.new(Base64.strict_decode64(e['keyValue']))
        d  = OpenSSL::Digest::SHA256.new
        ec.verify(d, Base64.strict_decode64(signature), signed_string)
      end.any?
    end

    def valid_mac?(mac_key, data, tag)
      d = OpenSSL::Digest::SHA256.new
      mac = OpenSSL::HMAC.digest(d, mac_key, Base64.strict_decode64(data))
      mac = Base64.strict_encode64(mac)

      return false if mac.length != tag.length

      Aliquot.compare(mac, tag)
    end
  end
end
