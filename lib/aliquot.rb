require 'json'
require 'base64'
require 'excon'
require 'hkdf'

require 'aliquot/validator'

$key_updater_semaphore = Mutex.new
$key_updater_thread = nil

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

  SIGNING_KEY_URL = 'https://payments.developers.google.com/paymentmethodtoken/keys.json'.freeze
  TEST_SIGNING_KEY_URL = 'https://payments.developers.google.com/paymentmethodtoken/test/keys.json'.freeze

  def self.start_key_updater(logger)
    source = if ENV['ENVIRONMENT'] == 'production'
               SIGNING_KEY_URL
             else
               TEST_SIGNING_KEY_URL
             end

    $key_updater_semaphore.synchronize do
      # Another thread might have been waiting for on the mutex
      break unless $key_updater_thread.nil?

      new_thread = Thread.new do
        loop do
          begin
            timeout = 0

            conn = Excon.new(source)
            resp = conn.get

            raise 'Unable to update keys: ' + resp.data[:status_line] unless resp.status == 200
            cache_control = resp.headers['Cache-Control'].to_s.split(/,\s*/)
            h = cache_control.map { |x| /\Amax-age=(?<timeout>\d+)\z/ =~ x; timeout }.compact

            timeout = h.first.to_i if h.length == 1
            timeout = 86400 if timeout.nil? || !timeout.positive?

            Thread.current.thread_variable_set('keys', resp.body)

            # Supposedly recommended by Tink library
            sleep_time = timeout / 2

            logger.info('Updated Google signing keys. Sleeping for: ' + (sleep_time / 86400.0).to_s + ' days')

            sleep sleep_time
          rescue Interrupt => e
            # When interrupted
            logger.fatal('Quitting: ' + e.message)
            return
          rescue => e
            # Don't retry excessively.
            logger.error('Exception updating Google signing keys: ' + e.message)
            sleep 1
          end
        end
      end

      sleep 0.2 while new_thread.thread_variable_get('keys').nil?
      # Body has now been set.
      # Let other clients through.
      $key_updater_thread = new_thread
    end
  end

  class Payment
    # Parameters:
    # token_string::  Google Pay token (JSON string)
    # shared_secret:: Base64 encoded shared secret (EC Public key)
    # merchant_id::   Google Pay merchant ID ("merchant:<SOMETHING>")
    # logger::        The logger to use, check DummyLogger for interface
    # signing_keys::  Formatted list of signing keys used to sign token contents.
    #                 Otherwise a thread continuously updating google signing
    #                 keys will be started.
    def initialize(token_string, shared_secret, merchant_id, logger = DummyLogger, signing_keys = nil)
      Aliquot.start_key_updater(logger) if $key_updater_thread.nil? && signing_keys.nil?
      @signing_keys = signing_keys

      @shared_secret = shared_secret
      @merchant_id = merchant_id
      @token_string = token_string
    end

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
      @signing_keys || $key_updater_thread.thread_variable_get('keys')
    end
  end

  class DummyLogger
    class << self
      def debug(message)
        print(message)
      end

      def info(message)
        print(message)
      end

      def warning(message)
        print(message)
      end

      def error(message)
        print(message)
      end

      def fatal(message)
        print(message)
      end

      private

      def print(message)
        puts(message)
      end
    end
  end
end
