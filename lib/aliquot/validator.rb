require 'json'
require 'dry-validation'

require 'base64'
require 'openssl'

module Aliquot
  module Validator
    # Verified according to:
    # https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#payment-method-token-structure
    module Predicates
      include Dry::Logic::Predicates

      CUSTOM_PREDICATE_ERRORS = {
        base64?:          'must be Base64',
        pan?:             'must be a pan',
        ec_public_key?:   'must be an EC public key',
        eci?:             'must be an ECI',
        json_string?:     'must be valid JSON',
        integer_string?:  'must be string encoded integer',
        month?:           'must be a month (1..12)',
        year?:            'must be a year (2000..3000)',
      }.freeze

      # Support Ruby 2.3, but use the faster #match? when available.
      match_b = ''.respond_to?(:match?) ? ->(s, re) { s.match?(re) } : ->(s, re) { !!(s =~ re) }

      predicate(:base64?) do |x|
        str?(x) &&
          match_b.call(x, /\A[=A-Za-z0-9+\/]*\z/) && # allowable chars
          x.length.remainder(4).zero? && # multiple of 4
          !match_b.call(x, /=[^$=]/) && # may only end with ='s
          !match_b.call(x, /===/) # at most 2 ='s
      end

      # We should figure out how strict we should be. Hopefully we can discard
      # the above Base64? predicate and use the following simpler one:
      #predicate(:strict_base64?) { |x| !!Base64.strict_decode64(x) rescue false }

      predicate(:pan?) { |x| str?(x) && match_b.call(x, /\A[1-9][0-9]{11,18}\z/) }

      predicate(:eci?) { |x| str?(x) && match_b.call(x, /\A\d{1,2}\z/) }

      predicate(:ec_public_key?) { |x| base64?(x) && OpenSSL::PKey::EC.new(Base64.decode64(x)).check_key rescue false }

      predicate(:json_string?) { |x| !!JSON.parse(x) rescue false }

      predicate(:integer_string?) { |x| match_b.call(x, /\A\d+\z/) }

      predicate(:month?) { |x| x.between?(1, 12) }

      predicate(:year?) { |x| x.between?(2000, 3000) }
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
      required(:protocolVersion).filled(:str?, eql?: 'ECv1')
      required(:signedMessage).filled(:str?, :json_string?)
    end

    SignedMessageSchema = Dry::Validation.Schema(BaseSchema) do
      required(:encryptedMessage).filled(:str?, :base64?)
      required(:ephemeralPublicKey).filled(:str?, :base64?)
      required(:tag).filled(:str?, :base64?)
    end

    PaymentMethodDetailsSchema = Dry::Validation.Schema(BaseSchema) do
      required(:pan).filled(:integer_string?, :pan?)
      required(:expirationMonth).filled(:int?, :month?)
      required(:expirationYear).filled(:int?, :year?)
      required(:authMethod).filled(:str?, included_in?: %w[PAN_ONLY CRYPTOGRAM_3DS])

      optional(:cryptogram).filled(:str?)
      optional(:eciIndicator).filled(:str?, :eci?)

      rule('when authMethod is CRYPTOGRAM_3DS, cryptogram': %i[authMethod cryptogram]) do |method, cryptogram|
        method.eql?('CRYPTOGRAM_3DS') > cryptogram.filled?
      end

      rule('when authMethod is PAN_ONLY, cryptogram': %i[authMethod cryptogram ]) do |method, cryptogram|
        method.eql?('PAN_ONLY') > cryptogram.none?
      end

      rule('when authMethod is PAN_ONLY, eciIndicator': %i[authMethod eciIndicator]) do |method, eci|
        method.eql?('PAN_ONLY') > eci.none?
      end
    end

    EncryptedMessageSchema = Dry::Validation.Schema(BaseSchema) do
      required(:messageExpiration).filled(:str?, :integer_string?)
      required(:messageId).filled(:str?)
      required(:paymentMethod).filled(:str?, eql?: 'CARD')
      required(:paymentMethodDetails).schema(PaymentMethodDetailsSchema)
    end

    module InstanceMethods
      attr_reader :output

      def validate
        @validation ||= @schema.call(@input)
        @output = @validation.output
        return true if @validation.success?
        raise Error, "validation error: #{errors_formatted}"
      end

      def valid?
        validate
      rescue
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
      class Error < ::Aliquot::Validation::Error; end
      def initialize(input)
        @input = input
        @schema = TokenSchema
      end
    end

    class SignedMessage
      include InstanceMethods
      class Error < ::Aliquot::Validation::Error; end
      def initialize(input)
        @input = input
        @schema = SignedMessageSchema
      end
    end

    class EncryptedMessageValidator
      include InstanceMethods
      class Error < ::Aliquot::Validation::Error; end
      def initialize(input)
        @input = input
        @schema = EncryptedMessageSchema
      end
    end
  end
end
