$LOAD_PATH.unshift File.dirname(__FILE__)

require 'json'
require 'r2d2'
require 'pry'

require 'aliquot/google_key_updater'
require 'aliquot/validator'

module Aliquot
  class ExpiredException < StandardError; end

  class Payment
    include R2D2::Util

    # Google Key updater.
    @@gku = nil

    def initialize(token_string, shared_secret, recipient_id)
      # Start the Google Key Updater thread if we haven't.
      # A mutex should be added here to avoid multiple creations
      if @@gku.nil?
        # Provide the initial keys to avoid race issues.
        #GoogleKeyUpdater.instance.keys = GoogleKeyUpdater.update_keys
        GoogleKeyUpdater.update_keys
        @@gku = Thread.new { GoogleKeyUpdater.updater }
      end

      @shared_secret = shared_secret
      @recipient_id = recipient_id
      @token_string = token_string
    end

    def process
      @token = JSON.parse(@token_string)

      validate(Aliquot::Validator::Token, @token)

      token = build_token(@token, @recipient_id, JSON.parse(GoogleKeyUpdater.update_keys))

      @signed_message = JSON.parse(token.signed_message)
      validate(Aliquot::Validator::SignedMessage, @signed_message)

      @message = decrypt

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

    def decrypt
      hkdf_keys = derive_hkdf_keys(@signed_message['ephemeralPublicKey'], Base64.decode64(@shared_secret), 'Google')
      verify_mac(hkdf_keys[:mac_key], @signed_message['encryptedMessage'], @signed_message['tag'])
      JSON.parse(
        decrypt_message(@signed_message['encryptedMessage'], hkdf_keys[:symmetric_encryption_key])
      )
    end

    def build_token(token, recipient, keys)
      # Use R2D2 to verify the token.
      R2D2.build_token(token,
                       recipient_id: recipient,
                       verification_keys: keys)
    end
  end
end
