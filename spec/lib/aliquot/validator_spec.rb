require 'aliquot/error'
require 'aliquot/validator'
require 'aliquot-pay'
require 'spec_helper'
require 'expectations/schema'

require 'json'

# Tests to make sure we enforce what we want in the validator.

shared_examples 'Validator Spec' do
  context 'TokenSchema' do
    let(:schema) { Aliquot::Validator::TokenContract.new }

    context 'signature' do
      it 'must exist' do
        token.delete('signature')
        is_expected.to dissatisfy_schema(schema, {signature: ['is missing']})
      end

      it 'must be filled' do
        generator.signature = ''
        is_expected.to dissatisfy_schema(schema, {signature: ['must be filled']})
      end

      it 'must be a string' do
        generator.signature = 123
        is_expected.to dissatisfy_schema(schema, {signature: ['must be a string']})
      end

      it 'must be base64' do
        generator.signature = 'not base64'
        is_expected.to dissatisfy_schema(schema, {signature: ['must be Base64', 'must be base64-encoded ANS.1 value']})
      end

      it 'must be asn1' do
        generator.signature = Base64.strict_encode64('base64')
        is_expected.to dissatisfy_schema(schema, {signature: ['must be base64-encoded ANS.1 value']})
      end
    end

    context 'protocolVersion' do
      it 'must exist' do
        token.delete('protocolVersion')
        is_expected.to dissatisfy_schema(schema, {protocolVersion: ['is missing']})
      end

      it 'must be filled' do
        token['protocolVersion'] = ''
        is_expected.to dissatisfy_schema(schema, {protocolVersion: ['must be filled']})
      end

      it 'must be a string' do
        token['protocolVersion'] = 123
        is_expected.to dissatisfy_schema(schema, {protocolVersion: ['must be a string']})
      end
    end

    context 'signedMessage' do
      it 'must exist' do
        token.delete('signedMessage')
        is_expected.to dissatisfy_schema(schema, {signedMessage: ['is missing']})
      end

      it 'must be filled' do
        token['signedMessage'] = ''
        is_expected.to dissatisfy_schema(schema, {signedMessage: ['must be filled']})
      end

      it 'must be a string' do
        generator.signed_message = 123
        is_expected.to dissatisfy_schema(schema, {signedMessage: ['must be a string']})
      end

      it 'must be valid JSON' do
        generator.signed_message = 'not valid json'
        is_expected.to dissatisfy_schema(schema, {signedMessage: ['must be valid JSON']})
      end
    end

    context 'SignedMessageScheme' do
      let(:schema) { Aliquot::Validator::SignedMessageContract.new }
      let(:token)  { generator.build_signed_message }

      context 'encryptedMessage' do
        it 'must exist' do
          token.delete('encryptedMessage')
          is_expected.to dissatisfy_schema(schema, {encryptedMessage: ['is missing']})
        end

        it 'must be filled' do
          token['encryptedMessage'] = ''
          is_expected.to dissatisfy_schema(schema, {encryptedMessage: ['must be filled']})
        end

        it 'must be a string' do
          generator.encrypted_message = 123
          is_expected.to dissatisfy_schema(schema, {encryptedMessage: ['must be a string']})
        end

        it 'must be base64' do
          generator.encrypted_message = 'not base64'
          is_expected.to dissatisfy_schema(schema, {encryptedMessage: ['must be Base64']})
        end
      end

      context 'ephemeralPublicKey' do
        it 'must exist' do
          token.delete('ephemeralPublicKey')
          is_expected.to dissatisfy_schema(schema, {ephemeralPublicKey: ['is missing']})
        end

        it 'must be filled' do
          token['ephemeralPublicKey'] = ''
          is_expected.to dissatisfy_schema(schema, {ephemeralPublicKey: ['must be filled']})
        end

        it 'must be a string' do
          generator.ephemeral_public_key = 123
          is_expected.to dissatisfy_schema(schema, {ephemeralPublicKey: ['must be a string']})
        end

        it 'must be base64' do
          generator.ephemeral_public_key = 'not base64'
          is_expected.to dissatisfy_schema(schema, {ephemeralPublicKey: ['must be Base64']})
        end
      end
    end
  end

  context 'EncryptedMessageSchema' do
    let(:schema) { Aliquot::Validator::EncryptedMessageContract.new }
    let(:token)  { generator.build_cleartext_message }

    context 'messageExpiration' do
      it 'must exist' do
        token.delete('messageExpiration')
        is_expected.to dissatisfy_schema(schema, {messageExpiration: ['is missing']})
      end

      it 'must be filled' do
        generator.message_expiration = ''
        is_expected.to dissatisfy_schema(schema, {messageExpiration: ['must be filled']})
      end

      it 'must be a string' do
        generator.message_expiration = 123
        is_expected.to dissatisfy_schema(schema, {messageExpiration: ['must be a string']})
      end

      it 'must be an integer string' do
        generator.message_expiration = 'not integer string'
        is_expected.to dissatisfy_schema(schema, {messageExpiration: ['must be string encoded integer']})
      end
    end

    context 'messageId' do
      it 'must exist' do
        token.delete('messageId')
        is_expected.to dissatisfy_schema(schema, {messageId: ['is missing']})
      end

      it 'must be filled' do
        generator.message_id = ''
        is_expected.to dissatisfy_schema(schema, {messageId: ['must be filled']})
      end

      it 'must be a string' do
        generator.message_id = 123
        is_expected.to dissatisfy_schema(schema, {messageId: ['must be a string']})
      end
    end

    context 'paymentMethod' do
      it 'must exist' do
        token.delete('paymentMethod')
        is_expected.to dissatisfy_schema(schema, {paymentMethod: ['is missing']})
      end

      it 'must be filled' do
        generator.payment_method = ''
        is_expected.to dissatisfy_schema(schema, {paymentMethod: ['must be filled']})
      end

      it 'must be a string' do
        generator.payment_method = 123
        is_expected.to dissatisfy_schema(schema, {paymentMethod: ['must be a string']})
      end

    end

    context 'paymentMethodDetails' do
      it 'must exist' do
        token.delete('paymentMethodDetails')
        is_expected.to dissatisfy_schema(schema, {paymentMethodDetails: ['is missing']})
      end

      it 'must be a JSON object' do
        generator.payment_method_details = 'not a json object'
        is_expected.to dissatisfy_schema(schema, {paymentMethodDetails: ['must be a hash']})
      end
    end
  end

  context 'SignedKeySchema' do
    let(:schema) { Aliquot::Validator::SignedKeyContract.new }
    let(:token)  { generator.build_signed_key }

    context 'keyExpiration' do
      it 'must exist' do
        token.delete('keyExpiration')
        is_expected.to dissatisfy_schema(schema, {keyExpiration: ['is missing']})
      end

      it 'must be filled' do
        token['keyExpiration'] = ''
        is_expected.to dissatisfy_schema(schema, {keyExpiration: ['must be filled']})
      end

      it 'must be integer string' do
        generator.key_expiration = 'not digits'
        is_expected.to dissatisfy_schema(schema, {keyExpiration: ['must be string encoded integer']})
      end
    end

    context 'keyValue' do
      it 'must exist' do
        token.delete('keyValue')
        is_expected.to dissatisfy_schema(schema, {keyValue: ['is missing']})
      end

      it 'must be filled' do
        token['keyValue'] = ''
        is_expected.to dissatisfy_schema(schema, {keyValue: ['must be filled']})
      end

      it 'must be ec_public_key' do
        generator.key_value = 'not EC public key'
        is_expected.to dissatisfy_schema(schema, {keyValue: ['must be an EC public key']})
      end
    end
  end
end

shared_examples 'ECv2 PaymentMethodDetails' do
  context 'IntermediateSigningKeySchema' do
    let(:schema) { Aliquot::Validator::IntermediateSigningKeyContract.new }
    let(:key)    { token['intermediateSigningKey'] }
    subject do
      key
    end

    context 'signedKey' do
      it 'must exist' do
        token['intermediateSigningKey'].delete('signedKey')
        is_expected.to dissatisfy_schema(schema, signedKey: ['is missing'])
      end

      it 'must be filled' do
        token['intermediateSigningKey']['signedKey'] = ''
        is_expected.to dissatisfy_schema(schema, signedKey: ['must be filled'])
      end

      it 'must be a string' do
        generator.signed_key_string = 122
        is_expected.to dissatisfy_schema(schema, signedKey: ['must be a string'])
      end

      # CB: Not sure how to trigger this test as JSON.parse has changed since 2.3
      #     see https://clearhaus.slack.com/archives/C3LG75WE9/p1661940442665459
      it 'must be valid json'

      it 'must pass' do
        expect(JSON.parse(key.to_json, symbolize_names: false)).to satisfy_schema(schema)
      end
    end

    context 'signatures' do
      it 'must exist' do
        token['intermediateSigningKey'].delete('signatures')
        is_expected.to dissatisfy_schema(schema, signatures: ['is missing'])
      end

      it 'must be filled' do
        generator.signatures = ''
        is_expected.to dissatisfy_schema(schema, signatures: ['must be an array'])
      end

      it 'must be an array' do
        generator.signatures = 'Not an array'
        is_expected.to dissatisfy_schema(schema, signatures: ['must be an array'])
      end

      it 'entries must be base64' do
        generator.signatures = ['Not base64']
        is_expected.to dissatisfy_schema(schema, signatures: {0 => ['must be Base64']})
      end

      it 'entries must be asn1' do
        generator.signatures = ['Not base64']
        is_expected.to dissatisfy_schema(schema, signatures: {0 => ['must be Base64']})
      end

      it 'must pass' do
        expect(JSON.parse(key.to_json, symbolize_names: false)).to satisfy_schema(schema)
      end
    end

    context 'intermediateSigningKey' do
      let(:schema) { Aliquot::Validator::TokenContract.new }
      subject do
        token
      end

      it 'must exist' do
        token.delete('intermediateSigningKey')
        is_expected.to dissatisfy_schema(schema, {intermediateSigningKey: ['is missing']})
      end

      it 'must be a JSON object' do
        generator.intermediate_signing_key = 'Not a JSON object'
        is_expected.to dissatisfy_schema(schema, {intermediateSigningKey: ['must be a hash']})
      end
    end
  end
end

shared_examples 'CommonPaymentMethodDetailsContract' do
  context 'PaymentMethodDetailsSchema' do
    let(:token)  { generator.build_payment_method_details }

    it 'must be filled' do
      generator.pan = ''
      is_expected.to dissatisfy_schema(schema, {pan: ['must be filled']})
    end

    it 'must be integer string' do
      generator.pan = 'no integers here'
      is_expected.to dissatisfy_schema(schema, {pan: ['must be string encoded integer', 'must be a PAN']})
    end

    it 'must be a pan' do
      generator.pan = '1121412908091872401284'
      is_expected.to dissatisfy_schema(schema, {pan: ['must be a PAN']})
    end
  end

  context 'expirationMonth' do
    it 'must exist' do
      token.delete('expirationMonth')
      is_expected.to dissatisfy_schema(schema, {expirationMonth: ['is missing']})
    end

    it 'must be filled' do
      generator.expiration_month = ''
      is_expected.to dissatisfy_schema(schema, {expirationMonth: ['must be filled']})
    end

    it 'must be an integer' do
      generator.expiration_month = 'a string'
      is_expected.to dissatisfy_schema(schema, {expirationMonth: ['must be an integer']})
    end

    it 'must be a month' do
      generator.expiration_month = 13
      is_expected.to dissatisfy_schema(schema, {expirationMonth: ['must be a month (1..12)']})
    end
  end

  context 'expirationYear' do
    it 'must exist' do
      token.delete('expirationYear')
      is_expected.to dissatisfy_schema(schema, {expirationYear: ['is missing']})
    end

    it 'must be filled' do
      generator.expiration_year = ''
      is_expected.to dissatisfy_schema(schema, {expirationYear: ['must be filled']})
    end

    it 'must be an integer' do
      generator.expiration_year = 'a string'
      is_expected.to dissatisfy_schema(schema, {expirationYear: ['must be an integer']})
    end

    it 'must be a year' do
      generator.expiration_year = 19993
      is_expected.to dissatisfy_schema(schema, {expirationYear: ['must be a year (2000..3000)']})
    end
  end

  context 'authMethod' do
    it 'must exist' do
      token.delete('authMethod')
      is_expected.to dissatisfy_schema(schema, {authMethod: ['is missing']})
    end

    it 'must be filled' do
      generator.auth_method = ''
      is_expected.to dissatisfy_schema(schema, {authMethod: ['must be filled']})
    end

    it 'must be a string' do
      generator.auth_method = 123
      is_expected.to dissatisfy_schema(schema, {authMethod: ['must be a string']})
    end

    it 'must be PAN_ONLY, CRYPTOGRAM_3DS' do
      generator.auth_method = 'INVALID_AUTH_METHOD'
      is_expected.to dissatisfy_schema(schema, {authMethod: ['must be one of: PAN_ONLY, CRYPTOGRAM_3DS, 3DS']})
    end
  end

  context 'cryptogram' do
    context 'when PAN_ONLY' do
      it 'must not exist' do
        token['cryptogram'] = '05'
        is_expected.to dissatisfy_schema(schema, {cryptogram: ['cannot be defined']})
      end
    end

    context 'when CRYPTOGRAM_3DS' do
      before(:each) { generator.auth_method = 'CRYPTOGRAM_3DS' }

      it 'must exist' do
        token.delete('cryptogram')
        is_expected.to dissatisfy_schema(schema, {cryptogram: ['is missing']})
      end

      it 'must be filled' do
        generator.cryptogram = ''
        is_expected.to dissatisfy_schema(schema, {cryptogram: ['must be filled']})
      end

      it 'must be a string' do
        generator.cryptogram = 123
        is_expected.to dissatisfy_schema(schema, {cryptogram: ['must be a string']})
      end
    end
  end

  context 'eciIndicator' do
    context 'when PAN_ONLY' do
      it 'must not exist' do
        token['eciIndicator'] = '05'
        is_expected.to dissatisfy_schema(schema, {eciIndicator: ['cannot be defined']})
      end
    end

    context 'when CRYPTOGRAM_3DS' do
      before(:each) { generator.auth_method = 'CRYPTOGRAM_3DS' }

      it 'is not required' do
        token.delete('eciIndicator')
        expect(JSON.parse(token.to_json, symbolize_names: false)).to satisfy_schema(schema)
      end

      it 'must be a string' do
        generator.eci_indicator = 123
        is_expected.to dissatisfy_schema(schema, {eciIndicator: ['must be a string']})
      end

      it 'must be an ECI' do
        generator.eci_indicator = 'ff'
        is_expected.to dissatisfy_schema(schema, {eciIndicator: ['must be an ECI']})
      end
    end
  end
end

describe Aliquot::Validator do
  describe 'ECv1' do
    subject do
      token
    end
    describe 'non-tokenized' do
      let(:generator) { AliquotPay.new(protocol_version: :ECv1, type: :browser) }
      let(:token)     { generator.token }
      include_examples 'Validator Spec'

      context 'pan' do
        let(:schema) { Aliquot::Validator::ECv1_PaymentMethodDetailsContract.new }
        let(:token)  { generator.build_cleartext_message['paymentMethodDetails'] }
        it 'must exist' do
          token.merge!('threedsCryptogram' => token.delete('3dsCryptogram'))
          token.delete('pan')
          is_expected.to dissatisfy_schema(schema, {pan: ['is missing']})
        end
      end

      context 'paymentMethod' do
        let(:token)  { generator.build_cleartext_message }
        let(:schema) { Aliquot::Validator::EncryptedMessageContract.new }
          it 'must be CARD for everything but tokenized ECv1' do
            generator.payment_method = 'RANDOM'
            is_expected.to dissatisfy_schema(schema, {paymentMethod: ['must be equal to CARD']})
          end
      end

      context 'intermediateSigningKey' do
        let(:schema) { Aliquot::Validator::TokenContract.new }
        let(:input)  { token }

        it 'should not be enforced' do
          token.delete('intermediateSigningKey')
          expect(JSON.parse(input.to_json, symbolize_names: false)).to satisfy_schema(schema)
        end
      end
    end

    describe 'tokenized' do
      let(:generator) { AliquotPay.new(protocol_version: :ECv1, type: :app) }
      let(:token)     { generator.token }
      include_examples 'Validator Spec'

      context 'dpan' do
        let(:schema) { Aliquot::Validator::ECv1_TokenizedPaymentMethodDetailsContract.new }
        let(:token)  { generator.build_cleartext_message['paymentMethodDetails'] }
        it 'must exist' do
          token.merge!('threedsCryptogram' => token.delete('3dsCryptogram'))
          token.delete('dpan')
          is_expected.to dissatisfy_schema(schema, {dpan: ['is missing']})
        end
      end

      context 'paymentMethod' do
        let(:token)  { generator.build_cleartext_message }
        let(:schema) { Aliquot::Validator::EncryptedMessageContract.new }
        it 'must be TOKENIZED_CARD for tokenized ECv1' do
          generator.payment_method = 'RANDOM'
          generator.auth_method = '3DS'
          token['protocolVersion'] = 'ECv1'
          is_expected.to dissatisfy_schema(schema, {paymentMethod: ['must be equal to TOKENIZED_CARD']})
        end
      end

      context 'intermediateSigningKey' do
        let(:schema) { Aliquot::Validator::TokenContract.new }

        it 'should not be enforced' do
          token.delete('intermediateSigningKey')
          expect(JSON.parse(token.to_json, symbolize_names: false)).to satisfy_schema(schema)
        end
      end
    end
  end

  context 'ECv2' do
    subject do
      token
    end
    context 'non-tokenized' do
      let(:generator) { AliquotPay.new(protocol_version: :ECv2, type: :browser) }
      let(:token)     { generator.token }
      include_examples 'Validator Spec'
      include_examples 'ECv2 PaymentMethodDetails'

      context 'pan' do
        let(:schema) { Aliquot::Validator::ECv2_PaymentMethodDetailsContract.new }
        let(:token)  { generator.build_cleartext_message['paymentMethodDetails'] }
        it 'must exist' do
          token.merge!('threedsCryptogram' => token.delete('3dsCryptogram'))
          token.delete('pan')
          is_expected.to dissatisfy_schema(schema, {pan: ['is missing']})
        end
      end

      context 'paymentMethod' do
        let(:token)  { generator.build_cleartext_message }
        let(:schema) { Aliquot::Validator::EncryptedMessageContract.new }
          it 'must be CARD for everything but tokenized ECv1' do
            generator.payment_method = 'RANDOM'
            is_expected.to dissatisfy_schema(schema, {paymentMethod: ['must be equal to CARD']})
          end
      end
    end

    context 'tokenized' do
      let(:generator) { AliquotPay.new(protocol_version: :ECv2, type: :app) }
      let(:token)     { generator.token }
      include_examples 'Validator Spec'
      include_examples 'ECv2 PaymentMethodDetails'

      context 'pan' do
        let(:schema) { Aliquot::Validator::ECv2_TokenizedPaymentMethodDetailsContract.new }
        let(:token)  { generator.build_cleartext_message['paymentMethodDetails'] }
        it 'must exist' do
          token.merge!('threedsCryptogram' => token.delete('3dsCryptogram'))
          token.delete('pan')
          is_expected.to dissatisfy_schema(schema, {pan: ['is missing']})
        end
      end

      context 'paymentMethod' do
        let(:token)  { generator.build_cleartext_message }
        let(:schema) { Aliquot::Validator::EncryptedMessageContract.new }
          it 'must be CARD for everything but tokenized ECv1' do
            generator.payment_method = 'RANDOM'
            is_expected.to dissatisfy_schema(schema, {paymentMethod: ['must be equal to CARD']})
          end
      end
    end
  end
end
