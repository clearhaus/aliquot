require 'json'
require 'base64'
require 'excon'
require 'hkdf'

require 'aliquot/validator'
require 'aliquot/error'

$key_updater_semaphore = Mutex.new
$key_updater_thread = nil

module Aliquot
  ##
  # Constant-time comparison function
  def self.compare(a, b)
    err = 0

    y = b.unpack('C*')

    a.each_byte do |x|
      err |= x ^ y.shift
    end

    err.zero?
  end

  ##
  # Keys used for signing in production
  SIGNING_KEY_URL = 'https://payments.developers.google.com/paymentmethodtoken/keys.json'.freeze

  ##
  # Keys used for signing in a testing environment
  TEST_SIGNING_KEY_URL = 'https://payments.developers.google.com/paymentmethodtoken/test/keys.json'.freeze

  ##
  # Start a thread that keeps the Google signing keys updated.
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
            cache_control = resp.headers['Cache-Control'].split(/,\s*/)
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
end
