require 'aliquot/error'
require 'spec_helper'

describe Aliquot::Validator::TokenSchema do
  let(:token) { AliquotPay.generate_token(@payment, key, recipient) }
  let(:token_string) { JSON.unparse(token) }

  subject do
    lambda do
      a = Aliquot::Payment.new(token_string, 'no_secret', 'no_id',
                               signing_keys: '')
      a.process
    end
  end

  context 'rejects bad signature' do
    [
      ['Not a signature', /signature[^\w]+must be Base64/],
      ['',                /signature[^\w]+must be filled/],
    ].each do |sig, msg|
      it "when sig is '#{sig}'" do
        @payment = AliquotPay.payment
        token['signature'] = sig
        is_expected.to raise_error(Aliquot::ValidationError, msg)
      end
    end
  end

  it 'rejects invalid protocolversion' do
    @payment = AliquotPay.payment
    token['protocolVersion'] = ''
    is_expected.to raise_error(Aliquot::ValidationError, /protocolVersion[^\w]+must be filled/)
  end

  context 'rejects invalid signedMessage' do
    [
      [112,          /signedMessage[^\w]+must be a string/],
      ['not JSON',   /signedMessage[^\w]+must be valid JSON/],
    ].each do |sig, msg|
      it "when message is '#{sig}'" do
        expect do
          @payment = AliquotPay.payment
          token['signedMessage'] = sig
          a = Aliquot::Payment.new(token_string, 'no_secret', merchant_id,
                                   signing_keys: keystring)

          a.process
        end.to raise_error(Aliquot::ValidationError, msg)
      end
    end
  end
end

describe Aliquot::Validator::SignedMessageSchema do
  # The message we are generating.
  let(:message) do
    {
      'encryptedMessage'   => Base64.strict_encode64('Message'),
      'ephemeralPublicKey' => 'BCZO9+2/+Ltykjtnrk0DebxFR4ZtFu5P08aIi3lljPMh3tngBzV1Xpcm1tyHzyPWXwgDCiVYCNfvkXXjw+rdrjI=',
      'tag'                => 'ZbJAxo9aRquwzoguk2Otsh9xjBDxXJRwYDYKUSztwDo=',
    }
  end

  let(:token) { AliquotPay.generate_token(@payment, key, recipient, message) }
  let(:token_string) { JSON.unparse(token) }

  subject do
    lambda do
      a = Aliquot::Payment.new(token_string, 'no_secret', merchant_id,
                               signing_keys: keystring)
      a.process
    end
  end

  context 'rejects invalid encryptedMessage' do
    [
      [112,          /encryptedMessage[^\w]+must be a string/],
      ['not Base64', /encryptedMessage[^\w]+must be Base64/],
    ].each do |msg, err|
      it "when msg is '#{msg}'" do
        message['encryptedMessage'] = msg
        @payment = AliquotPay.payment
        is_expected.to raise_error(Aliquot::ValidationError, err)
      end
    end
  end

  context 'ephemeralPublicKey' do
    [
      [112,          /ephemeralPublicKey[^\w]+must be a string/],
      ['not Base64', /ephemeralPublicKey[^\w]+must be Base64/],
    ].each do |msg, err|
      it "is rejected when: '#{msg}'" do
        message['ephemeralPublicKey'] = msg
        @payment = AliquotPay.payment
        is_expected.to raise_error(Aliquot::ValidationError, err)
      end
    end
  end

  context 'rejects invalid tag' do
    [
      [112,          /tag[^\w]+must be a string/],
      ['not Base64', /tag[^\w]+must be Base64/],
    ].each do |msg, err|
      it "is rejected when: '#{msg}'" do
        message['tag'] = msg
        @payment = AliquotPay.payment
        is_expected.to raise_error(Aliquot::ValidationError, err)
      end
    end
  end
end

describe Aliquot::Validator::EncryptedMessageSchema do
  let(:token) { AliquotPay.generate_token(@payment, key, recipient) }
  let(:token_string) { JSON.unparse(token) }

  let(:shared_secret) { extract_shared_secret(token, recipient) }

  subject do
    lambda do
      a = Aliquot::Payment.new(token_string, shared_secret, merchant_id,
                               signing_keys: keystring)
      a.process
    end
  end

  context 'messageExpiration' do
    [
      [112,            /messageExpiration[^\w]+must be a string/],
      ['notintstring', /messageExpiration[^\w]+must be string encoded integer/],
    ].each do |msg, err|
      it "is rejected when: '#{msg}'" do
        @payment = AliquotPay.payment
        @payment['messageExpiration'] = msg
        is_expected.to raise_error(Aliquot::ValidationError, err)
      end
    end
  end

  it 'rejects invalid messageId' do
    @payment = AliquotPay.payment
    @payment['messageId'] = 112
    is_expected.to raise_error(Aliquot::ValidationError, /messageId[^\w]+must be a string/)
  end

  context 'paymentMethod' do
    [
      [112,        /paymentMethod[^\w]+must be a string/],
      ['not CARD', /paymentMethod[^\w]+must be equal to CARD/],
    ].each do |msg, err|
      it "is rejected when: '#{msg}'" do
        @payment = AliquotPay.payment
        @payment['paymentMethod'] = msg
        is_expected.to raise_error(Aliquot::ValidationError, err)
      end
    end
  end

  it 'rejects missing paymentMethodDetails' do
    @payment = AliquotPay.payment
    @payment.delete('paymentMethodDetails')
    is_expected.to raise_error(Aliquot::ValidationError, /paymentMethodDetails[^\w]+is missing/)
  end
end

describe Aliquot::Validator::PaymentMethodDetailsSchema do
  let(:token) { AliquotPay.generate_token(@payment, key, recipient) }
  let(:token_string) { JSON.unparse(token) }

  let(:shared_secret) { extract_shared_secret(token, recipient) }

  subject do
    lambda do
      a = Aliquot::Payment.new(token_string, shared_secret, merchant_id,
                               signing_keys: keystring)
      a.process
    end
  end

  context 'pan' do
    [
      [112,            /pan[^\w]+must be string encoded integer/],
      ['notintstring', /pan[^\w]+must be string encoded integer/],
      [nil,            /pan[^\w]+must be filled/],
    ].each do |msg, err|
      it "is rejected when: '#{msg}'" do
        @payment = AliquotPay.payment
        @payment['paymentMethodDetails']['pan'] = msg
        is_expected.to raise_error(Aliquot::ValidationError, err)
      end
    end
  end

  context 'expirationMonth' do
    [
      [112,            /expirationMonth[^\w]+must be a month/],
      ['notintstring', /expirationMonth[^\w]+must be an integer/],
      [nil,            /expirationMonth[^\w]+must be filled/],
    ].each do |msg, err|
      it "is rejected when: '#{msg}'" do
        @payment = AliquotPay.payment
        @payment['paymentMethodDetails']['expirationMonth'] = msg
        is_expected.to raise_error(Aliquot::ValidationError, err)
      end
    end
  end

  context 'expirationYear' do
    [
      [112,            /expirationYear[^\w]+must be a year/],
      ['notintstring', /expirationYear[^\w]+must be an integer/],
      [nil,            /expirationYear[^\w]+must be filled/],
    ].each do |msg, err|
      it "is rejected when: '#{msg}'" do
        @payment = AliquotPay.payment
        @payment['paymentMethodDetails']['expirationYear'] = msg
        is_expected.to raise_error(Aliquot::ValidationError, err)
      end
    end
  end

  context 'authMethod' do
    [
      [112,            /authMethod[^\w]+must be a string/],
      ['notintstring', /authMethod[^\w]+must be one of/],
      [nil,            /authMethod[^\w]+must be filled/],
    ].each do |msg, err|
      it "is rejected when: '#{msg}'" do
        @payment = AliquotPay.payment
        @payment['paymentMethodDetails']['authMethod'] = msg
        is_expected.to raise_error(Aliquot::ValidationError, err)
      end
    end
  end

  it 'accepts ECI data when CRYPTOGRAM_3DS' do
    @payment = AliquotPay.payment(auth_method: :CRYPTOGRAM_3DS)
    is_expected.to be_truthy
  end

  it 'accepts missing eciIndicator when CRYPTOGRAM_3DS' do
    @payment = AliquotPay.payment(auth_method: :CRYPTOGRAM_3DS)
    @payment['paymentMethodDetails'].delete('eciIndicator')
    is_expected.to be_truthy
  end

  it 'rejects missing cryptogram when CRYPTOGRAM_3DS' do
    @payment = AliquotPay.payment(auth_method: :CRYPTOGRAM_3DS)
    @payment['paymentMethodDetails'].delete('cryptogram')
    is_expected.to raise_error(Aliquot::ValidationError, /when authMethod is CRYPTOGRAM_3DS, cryptogram must be filled/)
  end

  it 'rejects ECI data when CARD' do
    @payment = AliquotPay.payment(auth_method: :PAN_ONLY)
    @payment['paymentMethodDetails']['eciIndicator'] = '05'
    is_expected.to raise_error(Aliquot::ValidationError, /when authMethod is PAN_ONLY, eciIndicator cannot be defined/)
  end

  it 'rejects cryptogram data when CARD' do
    @payment = AliquotPay.payment(auth_method: :PAN_ONLY)
    @payment['paymentMethodDetails']['cryptogram'] = 'some cryptogram'
    is_expected.to raise_error(Aliquot::ValidationError, /when authMethod is PAN_ONLY, cryptogram cannot be defined/)
  end

  it 'rejects invalid ECI indicator' do
    @payment = AliquotPay.payment(auth_method: :PAN_ONLY)
    @payment['paymentMethodDetails']['eciIndicator'] = 'not an ECI'
    is_expected.to raise_error(Aliquot::ValidationError, /eciIndicator must be an ECI/)
  end

  it 'rejects invalid cryptogram' do
    @payment = AliquotPay.payment(auth_method: :PAN_ONLY)
    @payment['paymentMethodDetails']['cryptogram'] = 124
    is_expected.to raise_error(Aliquot::ValidationError, /cryptogram must be a string/)
  end
end
