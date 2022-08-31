require 'aliquot/error'

require 'base64'
require 'dry-validation'
require 'json'
require 'openssl'

module Aliquot
  module Validator
    # Verified according to:
    # https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#payment-method-token-structure

    CUSTOM_PREDICATE_ERRORS = {
      is_base64: 'must be Base64',
      is_pan: 'must be a pan',
      is_ec_public_key: 'must be an EC public key',
      is_eci: 'must be an ECI',
      is_integer_string: 'must be string encoded integer',
      is_month: 'must be a month (1..12)',
      is_year: 'must be a year (2000..3000)',
      is_base64_asn1: 'must be base64 encoded asn1 value',
      is_json: 'must be valid JSON',

      is_authMethodCryptogram3DS: 'authMethod CRYPTOGRAM_3DS requires eciIndicator',
      is_authMethodCard: 'eciIndicator/cryptogram must be omitted when PAN_ONLY',
    }.freeze

    def self.base64_check(value)
      /\A[=A-Za-z0-9+\/]*\z/.match?(value) &&
        value.length.remainder(4).zero? &&
        !/=[^$=]/.match?(value) &&
        !/===/.match?(value)
    end

    Dry::Validation.register_macro(:is_base64) do
      if key?
        unless Aliquot::Validator.base64_check(value)
          key.failure(CUSTOM_PREDICATE_ERRORS[:is_base64])
        end
      end
    end

    def self.ans1_check(value)
      OpenSSL::ASN1.decode(Base64.strict_decode64(value)) rescue false
    end

    Dry::Validation.register_macro(:is_base64_asn1) do
      if key?
        unless Aliquot::Validator.ans1_check(value)
          key.failure(CUSTOM_PREDICATE_ERRORS[:is_base64_asn1])
        end
      end
    end

    Dry::Validation.register_macro(:is_pan) do
      if key?
        unless /\A[1-9][0-9]{11,18}\z/.match?(value)
          key.failure(CUSTOM_PREDICATE_ERRORS[:is_pan])
        end
      end
    end

    Dry::Validation.register_macro(:is_ec_public_key) do
      if key?
        ec = -> () { OpenSSL::PKey::EC.new(Base64.decode64(value)).check_key rescue false }.call
        unless :is_base64 && ec
          key.failure(CUSTOM_PREDICATE_ERRORS[:is_ec_public_key])
        end
      end
    end

    Dry::Validation.register_macro(:is_eci) do
      if key?
        unless /\A\d{1,2}\z/.match?(value)
          key.failure(CUSTOM_PREDICATE_ERRORS[:is_eci])
        end
      end
    end

    Dry::Validation.register_macro(:is_integer_string) do
      if key?
        unless /\A\d+\z/.match?(value)
          key.failure(CUSTOM_PREDICATE_ERRORS[:is_integer_string])
        end
      end
    end

    Dry::Validation.register_macro(:is_json) do
      if key?
        is_json = -> () { !!JSON.parse(value) rescue false }.call
        unless is_json
          key.failure(CUSTOM_PREDICATE_ERRORS[:is_json])
        end
      end
    end

    Dry::Validation.register_macro(:is_month) do
      if key?
        unless value.between?(1, 12)
          key.failure(CUSTOM_PREDICATE_ERRORS[:is_month])
        end
      end
    end

    Dry::Validation.register_macro(:is_year) do
      if key?
        unless value.between?(2000, 3000)
          key.failure(CUSTOM_PREDICATE_ERRORS[:is_year])
        end
      end
    end

    class SignedKeyContract < Dry::Validation::Contract
      json do
        required(:keyExpiration).filled(:str?)
        required(:keyValue).filled(:str?)
      end
      rule(:keyExpiration).validate(:is_integer_string)
      rule(:keyValue).validate(:is_ec_public_key)
    end
    SignedKeySchema = SignedKeyContract.new

    # Schema used for the 'intermediateSigningKey' hash included in ECv2.
    class IntermediateSigningKeyContract < Dry::Validation::Contract
      json do
        required(:signedKey).filled(:str?)
        required(:signatures).array(:str?)
      end
      rule(:signedKey).validate(:is_json)
      rule(:signatures).each do
        key.failure('must be Base64') unless Aliquot::Validator.base64_check(value) &&
          Aliquot::Validator.ans1_check(value)
      end
    end
    IntermediateSigningKeySchema = IntermediateSigningKeyContract.new

    # DRY-Validation schema for Google Pay token
    class TokenContract < Dry::Validation::Contract
      json do
        required(:signature).filled(:str?)
        required(:signedMessage).filled(:str?)
        required(:protocolVersion).filled(:str?)
        optional(:intermediateSigningKey).filled(:hash?).schema(IntermediateSigningKeyContract.new.schema)
      end
      rule(:signature).validate(:is_base64, :is_base64_asn1)
      rule(:signedMessage).validate(:is_json)

      # Old rule:
      # required(:protocolVersion).filled(:str?).when(eql?: 'ECv2') do
      #   required(:intermediateSigningKey)
      # end
      #
      # if :protocolVersion is 'ECv2' => require :intermediateSigningKey
      rule(:intermediateSigningKey) do
        key.failure('is missing') if 'ECv2'.eql?(values[:protocolVersion]) &&
          values[:intermediateSigningKey].nil?
      end
    end
    TokenSchema = TokenContract.new

    # DRY-Validation schema for signedMessage component Google Pay token
    class SignedMessageContract < Dry::Validation::Contract
      json do
        required(:encryptedMessage).filled(:str?)
        required(:ephemeralPublicKey).filled(:str?)
        required(:tag).filled(:str?)
      end
      rule(:encryptedMessage).validate(:is_base64)
      rule(:ephemeralPublicKey).validate(:is_base64)
      rule(:tag).validate(:is_base64)
    end
    SignedMessageSchema = SignedMessageContract.new

    # DRY-Validation schema for paymentMethodDetails component Google Pay token
    class PaymentMethodDetailsContract < Dry::Validation::Contract
      json do
        required(:pan).filled(:str?)
        required(:expirationMonth).filled(:int?)
        required(:expirationYear).filled(:int?)
        required(:authMethod).filled(:str?, included_in?: %w[PAN_ONLY CRYPTOGRAM_3DS])

        optional(:cryptogram).filled(:str?)
        optional(:eciIndicator).filled(:str?)
      end
      rule(:pan).validate(:is_integer_string, :is_pan)
      rule(:expirationMonth).validate(:is_month)
      rule(:expirationYear).validate(:is_year)
      rule(:eciIndicator).validate(:is_eci)

      # Old rule:
      # rule(cryptogram: %i[authMethod cryptogram]) do |method, cryptogram|
      #   method.eql?('CRYPTOGRAM_3DS') > required(:cryptogram)
      # end
      #
      # if :authMethod is 'CRYPTOGRAM_3DS' => require :cryptogram
      rule(:cryptogram) do
        key.failure('is missing') if 'CRYPTOGRAM_3DS'.eql?(values[:authMethod]) &&
          values[:cryptogram].nil?
      end

      # Old rule:
      # rule(cryptogram: %i[authMethod cryptogram]) do |method, cryptogram|
      #   method.eql?('PAN_ONLY').then(cryptogram.none?)
      # end
      #
      # if :authMethod is 'PAN_ONLY' => no :cryptogram
      rule(:cryptogram) do
        key.failure('cannot be defined') if 'PAN_ONLY'.eql?(values[:authMethod]) &&
          !values[:cryptogram].nil?
      end

      # Old rule:
      # rule(eciIndicator: %i[authMethod eciIndicator]) do |method, eci|
      #   method.eql?('PAN_ONLY').then(eci.none?)
      # end
      #
      # if :authMethod is 'PAN_ONLY' => no :eciIndicator
      rule(:eciIndicator) do
        key.failure('cannot be defined') if 'PAN_ONLY'.eql?(values[:authMethod]) &&
          !values[:eciIndicator].nil?
      end
    end
    PaymentMethodDetailsSchema = PaymentMethodDetailsContract.new

    # DRY-Validation schema for encryptedMessage component Google Pay token
    class EncryptedMessageContract < Dry::Validation::Contract
      json do
        required(:messageExpiration).filled(:str?)
        required(:messageId).filled(:str?)
        required(:paymentMethod).filled(:str?)
        required(:paymentMethodDetails).filled(:hash).schema(PaymentMethodDetailsContract.schema)
      end
      rule(:messageExpiration).validate(:is_integer_string)
      rule(:paymentMethod) do
        key.failure('must be equal to CARD') unless 'CARD'.eql?(value)
      end
    end
    EncryptedMessageSchema = EncryptedMessageContract.new

    module InstanceMethods
      attr_reader :output

      def validate
        @validation ||= @schema.call(@input)
        @output = @validation.values.data
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
