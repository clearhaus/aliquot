require 'aliquot/error'

require 'base64'
require 'dry-validation'
require 'json'
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
        base64_asn1?:     'must be base64 encoded asn1 value',

        authMethodCryptogram3DS: 'authMethod CRYPTOGRAM_3DS requires eciIndicator',
        authMethodCard:          'eciIndicator/cryptogram must be omitted when PAN_ONLY',
      }.freeze

      # Support Ruby 2.3, but use the faster #match? when available.
      match_b = ''.respond_to?(:match?) ? ->(s, re) { s.match?(re) } : ->(s, re) { !!(s =~ re) }

      def self.to_bool(lbd)
        lbd.call
        true
      rescue
        false
      end

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

      predicate(:pan?) { |x| match_b.call(x, /\A[1-9][0-9]{11,18}\z/) }

      predicate(:eci?) { |x| str?(x) && match_b.call(x, /\A\d{1,2}\z/) }

      predicate(:ec_public_key?) { |x| base64?(x) && OpenSSL::PKey::EC.new(Base64.decode64(x)).check_key rescue false }

      predicate(:json_string?) { |x| !!JSON.parse(x) rescue false }

      predicate(:integer_string?) { |x| str?(x) && match_b.call(x, /\A\d+\z/) }

      predicate(:month?) { |x| x.between?(1, 12) }

      predicate(:year?) { |x| x.between?(2000, 3000) }

      predicate(:base64_asn1?) { |x| OpenSSL::ASN1.decode(Base64.strict_decode64(x)) rescue false }
    end

    # Base for DRY-Validation schemas used in Aliquot.
    class BaseSchema < Dry::Validation::Schema::JSON
      predicates(Predicates)
      def self.messages
        super.merge(en: { errors: Predicates::CUSTOM_PREDICATE_ERRORS })
      end
    end

    # Schema used for the 'intermediateSigningKey' hash included in ECv2.
    IntermediateSigningKeySchema = Dry::Validation.Schema(BaseSchema) do
      required(:signedKey).filled(:str?, :json_string?)

      # TODO: Check if elements of array are valid signatures
      required(:signatures).filled(:array?) { each { base64? & base64_asn1? } }
    end

    SignedKeySchema = Dry::Validation.Schema(BaseSchema) do
      required(:keyExpiration).filled(:integer_string?)
      required(:keyValue).filled(:ec_public_key?)
    end

    # DRY-Validation schema for Google Pay token
    TokenSchema = Dry::Validation.Schema(BaseSchema) do
      required(:signature).filled(:str?, :base64?, :base64_asn1?)

      # Currently supposed to be ECv1, but may evolve.
      required(:protocolVersion).filled(:str?)
      required(:signedMessage).filled(:str?, :json_string?)

      optional(:intermediateSigningKey).schema(IntermediateSigningKeySchema)

      rule('ECv2 implies intermediateSigningKey': %i[protocolVersion intermediateSigningKey]) do |version, intermediatekey|
        version.eql?('ECv2') > intermediatekey.filled?
      end
    end

    # DRY-Validation schema for signedMessage component Google Pay token
    SignedMessageSchema = Dry::Validation.Schema(BaseSchema) do
      required(:encryptedMessage).filled(:str?, :base64?)
      required(:ephemeralPublicKey).filled(:str?, :base64?).value(size?: 44)
      required(:tag).filled(:str?, :base64?)
    end

    # DRY-Validation schema for paymentMethodDetails component Google Pay token
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

      rule('when authMethod is PAN_ONLY, eciIndicator': %i[authMethod eciIndicator]) do |method, eci|
        method.eql?('PAN_ONLY').then(eci.none?)
      end

      rule('when authMethod is PAN_ONLY, cryptogram': %i[authMethod cryptogram]) do |method, cryptogram|
        method.eql?('PAN_ONLY').then(cryptogram.none?)
      end
    end

    # DRY-Validation schema for encryptedMessage component Google Pay token
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
        raise Aliquot::ValidationError, "validation error(s), #{errors_formatted}"
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

    # Class for validating a Google Pay token
    class Token
      include InstanceMethods
      class Error < ::Aliquot::Error; end
      def initialize(input)
        @input = input
        @schema = TokenSchema
      end
    end

    # Class for validating the SignedMessage component of a Google Pay token
    class SignedMessage
      include InstanceMethods
      class Error < ::Aliquot::Error; end
      def initialize(input)
        @input = input
        @schema = SignedMessageSchema
      end
    end

    # Class for validating the encryptedMessage component of a Google Pay token
    class EncryptedMessageValidator
      include InstanceMethods
      class Error < ::Aliquot::Error; end
      def initialize(input)
        @input = input
        @schema = EncryptedMessageSchema
      end
    end

    class SignedKeyValidator
      include InstanceMethods
      class Error < ::Aliquot::Error; end
      def initialize(input)
        @input = input
        @schema = SignedKeySchema
      end
    end
  end
end
