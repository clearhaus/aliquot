require 'aliquot/error'

require 'base64'
require 'dry-validation'
require 'json'
require 'openssl'

module Aliquot
  module Validator
    # Verified according to:
    # https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#payment-method-token-structure

    CUSTOM_ERRORS = {
      base64?:         'must be Base64',
      pan?:            'must be a PAN',
      ec_public_key?:  'must be an EC public key',
      eci?:            'must be an ECI',
      integer_string?: 'must be string encoded integer',
      month?:          'must be a month (1..12)',
      year?:           'must be a year (2000..3000)',
      base64_asn1?:    'must be base64-encoded ANS.1 value',
      json?:           'must be valid JSON',

      is_authMethodCryptogram3DS: 'authMethod CRYPTOGRAM_3DS requires eciIndicator',
      is_authMethodCard:          'eciIndicator/cryptogram must be omitted when PAN_ONLY',
    }.freeze

    def self.base64_check(value)
      /\A[=A-Za-z0-9+\/]*\z/.match?(value) && # allowable chars
        value.length.remainder(4).zero? && # multiple of 4
        !/=[^$=]/.match?(value) && # may only end with ='s
        !/===/.match?(value) # at most 2 ='s
    end

    Dry::Validation.register_macro(:base64?) do
      if key?
        unless Aliquot::Validator.base64_check(value)
          key.failure(CUSTOM_ERRORS[:base64?])
        end
      end
    end

    def self.ans1_check(value)
      OpenSSL::ASN1.decode(Base64.strict_decode64(value)) rescue false
    end

    Dry::Validation.register_macro(:base64_asn1?) do
      if key?
        unless Aliquot::Validator.ans1_check(value)
          key.failure(CUSTOM_ERRORS[:base64_asn1?])
        end
      end
    end

    Dry::Validation.register_macro(:pan?) do
      if key?
        unless /\A[1-9][0-9]{11,18}\z/.match?(value)
          key.failure(CUSTOM_ERRORS[:pan?])
        end
      end
    end

    Dry::Validation.register_macro(:ec_public_key?) do
      if key?
        begin
          OpenSSL::PKey::EC.new(Base64.decode64(value)).check_key
        rescue
          key.failure(CUSTOM_ERRORS[:ec_public_key?])
        end
      end
    end

    Dry::Validation.register_macro(:eci?) do
      if key?
        unless /\A\d{1,2}\z/.match?(value)
          key.failure(CUSTOM_ERRORS[:eci?])
        end
      end
    end

    Dry::Validation.register_macro(:integer_string?) do
      if key?
        unless /\A\d+\z/.match?(value)
          key.failure(CUSTOM_ERRORS[:integer_string?])
        end
      end
    end

    Dry::Validation.register_macro(:json?) do
      if key?
        json = JSON.parse(value) rescue false
        key.failure(CUSTOM_ERRORS[:json?]) unless json
      end
    end

    Dry::Validation.register_macro(:month?) do
      if key?
        unless value.between?(1, 12)
          key.failure(CUSTOM_ERRORS[:month?])
        end
      end
    end

    Dry::Validation.register_macro(:year?) do
      if key?
        unless value.between?(2000, 3000)
          key.failure(CUSTOM_ERRORS[:year?])
        end
      end
    end

    class SignedKeyContract < Dry::Validation::Contract
      json do
        required(:keyExpiration).filled(:str?)
        required(:keyValue).filled(:str?)
      end
      rule(:keyExpiration).validate(:integer_string?)
      rule(:keyValue).validate(:ec_public_key?)
    end

    SignedKeySchema = SignedKeyContract.new

    # Schema used for the 'intermediateSigningKey' hash included in ECv2.
    class IntermediateSigningKeyContract < Dry::Validation::Contract
      json do
        required(:signedKey).filled(:str?)
        required(:signatures).array(:str?)
      end
      rule(:signedKey).validate(:json?)
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
        optional(:intermediateSigningKey).hash(IntermediateSigningKeyContract.new.schema)
      end
      rule(:signature).validate(:base64?, :base64_asn1?)
      rule(:signedMessage).validate(:json?)

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
      rule(:encryptedMessage).validate(:base64?)
      rule(:ephemeralPublicKey).validate(:base64?)
      rule(:tag).validate(:base64?)
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
      rule(:pan).validate(:integer_string?, :pan?)
      rule(:expirationMonth).validate(:month?)
      rule(:expirationYear).validate(:year?)
      rule(:eciIndicator).validate(:eci?)

      rule(:cryptogram) do
        key.failure('is missing') if 'CRYPTOGRAM_3DS'.eql?(values[:authMethod]) &&
          values[:cryptogram].nil?
      end

      rule(:cryptogram) do
        key.failure('cannot be defined') if 'PAN_ONLY'.eql?(values[:authMethod]) &&
          !values[:cryptogram].nil?
      end

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
        optional(:gatewayMerchantId).filled(:str?)
      end
      rule(:messageExpiration).validate(:integer_string?)
      rule(:paymentMethod) do
        key.failure('must be equal to CARD') unless 'CARD'.eql?(value)
      end
    end

    EncryptedMessageSchema = EncryptedMessageContract.new

    module InstanceMethods
      attr_reader :output

      def validate
        @validation ||= @schema.call(@input)
        @output = @validation.to_h
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
