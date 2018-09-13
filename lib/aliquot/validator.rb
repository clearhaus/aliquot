require 'json'
require 'dry-validation'

require 'base64'
require 'openssl'

module Aliquot
  module Validator
    module Predicates
      include Dry::Logic::Predicates

      CUSTOM_PREDICATE_ERRORS = {
        base64?:          'must be Base64',
        hex?:             'must be hex',
        pan?:             'must be a pan',
        yymmdd?:          'must be formatted YYMMDD',
        ec_public_key?:   'must be an EC public key',
        pkcs7_signature?: 'must be a PKCS7 Signature',
        eci?:             'must be an ECI',
        hex_sha256?:      'must be a hex-encoded SHA-256',
        base64_sha256?:   'must be a Base64-encoded SHA-256',
        iso4217_numeric?: 'must be an ISO 4217 numeric code',
        json?:            'must be valid JSON',
        intstring?:       'must be string encoded integer',
        month?:           'must be a month (1..12)',
        year?:            'must be a year (2000..3000)',
      }.freeze

      # Support Ruby 2.3, but use the faster #match? when available.
      match_b = ''.respond_to?(:match?) ? ->(s, re) { s.match?(re) } : ->(s, re) { !!(s =~ re) }

      predicate(:base64?) do |x|
        str?(x) &&
          match_b.(x, /\A[=A-Za-z0-9+\/]*\z/) && # allowable chars
          x.length.remainder(4).zero? && # multiple of 4
          !match_b.(x, /=[^$=]/) && # may only end with ='s
          !match_b.(x, /===/) # at most 2 ='s
      end

      # We should figure out how strict we should be. Hopefully we can discard
      # the above Base64? predicate and use the following simpler one:
      #predicate(:strict_base64?) { |x| !!Base64.strict_decode64(x) rescue false }

      predicate(:pan?) { |x| str?(x) && match_b.(x, /\A[1-9][0-9]{11,18}\z/) }

      predicate(:eci?) { |x| str?(x) && match_b.(x, /\A\d{1,2}\z/) }

      predicate(:ec_public_key?) { |x| base64?(x) && OpenSSL::PKey::EC.new(Base64.decode64(x)).check_key rescue false }

      predicate(:pkcs7_signature?) { |x| base64?(x) && !!OpenSSL::PKCS7.new(Base64.decode64(x)) rescue false }

      predicate(:json?) { |x| JSON.parse(x) rescue false }

      predicate(:intstring?) { |x| match_b.(x, /\d+/) }

      predicate(:month?) { |x| x >= 1 && x <= 12 }

      predicate(:year?) { |x| x >= 2000 && x <= 3000 }
    end

    class Error < StandardError; end

    class BaseSchema < Dry::Validation::Schema::JSON
      predicates(Predicates)
      def self.messages
        super.merge(en: { errors: Predicates::CUSTOM_PREDICATE_ERRORS })
      end
    end

    TokenSchema = Dry::Validation.Schema(BaseSchema) do
      required(:signature).filled(:str?, :base64?)
      required(:protocolVersion).filled(:str?, included_in?: %w[ECv1])
      required(:signedMessage).filled(:str?, :json?)
    end

    SignedMessageSchema = Dry::Validation.Schema(BaseSchema) do
      required(:encryptedMessage).filled(:str?, :base64?)
      required(:ephemeralPublicKey).filled(:str?, :base64?)
      required(:tag).filled(:str?, :base64?)
    end

    PaymentMethodDetails = Dry::Validation.Schema(BaseSchema) do
      required(:pan).filled(:pan?)
      required(:expirationMonth).filled(:int?, :month?)
      required(:expirationYear).filled(:int?, :year?)
      required(:authMethod).filled(:str?, included_in?: %w[PAN_ONLY CRYPTOGRAM_3DS])

      optional(:cryptogram).filled(:str?)
      optional(:eciIndicator).filled(:str?, :eci?)

      rule(cryptogram3ds: [:authMethod, :cryptogram]) do |method, cryptogram|
        method.eql?('CRYPTOGRAM_3DS') > cryptogram.filled?
      end
    end

    EncryptedMessage = Dry::Validation.Schema(BaseSchema) do
      required(:messageExpiration).filled(:str?, :intstring?)
      required(:messageId).filled(:str?)
      required(:paymentMethod).filled(:str?, included_in?: %w[CARD])
      required(:paymentMethodDetails).schema(PaymentMethodDetails)
    end

    module InstanceMethods
      attr_reader :output

      def validate
        @validation ||= @schema.call(@input)

        @output = @validation.output

        return true if @validation.success?

        raise Error, "validation error: #{@validation.errors.keys.join(', ')}"
      end

      def valid?
        validate
      rescue Error
        false
      end

      def errors
        valid? unless @validation

        @validation.errors
      end

      def errors_formatted(node = [errors])
        node.pop.flat_map do |key, value|
          if value.is_a?(Array)
            value.map { |error| "#{(node + [key]).join('.')} #{error}" }
          else
            errors_formatted(node + [key, value])
          end
        end
      end
    end

    class Token
      include InstanceMethods
      class Error < StandardError; end
      def initialize(input)
        @input = input
        @schema = TokenSchema
      end
    end

    class SignedMessage
      include InstanceMethods
      class Error < StandardError; end
      def initialize(input)
        @input = input
        @schema = SignedMessageSchema
      end
    end

    class EncryptedMessageValidator
      include InstanceMethods
      class Error < StandardError; end
      def initialize(input)
        @input = input
        @schema = EncryptedMessage
      end
    end
  end
end
