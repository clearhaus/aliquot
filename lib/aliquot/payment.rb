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
                   logger: Logger.new($stdout), signing_keys: nil)
      Aliquot.start_key_updater(logger) if $key_updater_thread.nil? && signing_keys.nil?
      @signing_keys = signing_keys

      @shared_secret = shared_secret
      @merchant_id = merchant_id
      @token_string = token_string
    end

    ##
    # Validate and decrypt the token.
    def process
      @token = JSON.parse(@token_string)
      validate(Aliquot::Validator::Token, @token)

      @protocol_version = @token['protocolVersion']

      raise Error, 'only ECv1 protocolVersion is supported' unless @protocol_version == 'ECv1'

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

    ##
    # Check if the token is expired, according to the messageExpiration included
    # in the token.
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
      # Generate the string that was signed.
      signed_string = ['Google', @merchant_id, @protocol_version, message].map do |str|
        [str.length].pack('V') + str
      end.join

      keys = JSON.parse(signing_keys)['keys']
      # Check if signature was performed with any possible key.
      keys.map do |e|
        next if e['protocolVersion'] != @protocol_version

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

    def signing_keys
      # Prefer static signing keys, otherwise fetch from updating thread.
      @signing_keys || $key_updater_thread.thread_variable_get('keys')
    end
  end
end
