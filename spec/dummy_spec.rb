require 'aliquot'

require 'aliquot-pay'

require 'spec_helper'

require 'base64'
require 'json'

describe Aliquot::Payment do
  let(:recipient) { OpenSSL::PKey::EC.new('prime256v1').generate_key }
  let(:merchant_id) { AliquotPay::DEFAULTS[:merchant_id] }

  # Trusted key used for signing.
  let(:key) { OpenSSL::PKey::EC.new('prime256v1').generate_key }
  let(:keystring) do
    public_key = OpenSSL::PKey::EC.new(key.group)
    public_key.public_key = key.public_key
    JSON.unparse(
      'keys' => [
        {
          'keyValue'        => Base64.strict_encode64(public_key.to_der),
          'protocolVersion' => 'ECv1',
        },
      ]
    )
  end

  let(:token) { AliquotPay.generate_token(@payment, key, recipient) }
  let(:token_string) { JSON.unparse(token) }

  let(:shared_secret) { extract_shared_secret(token, recipient) }

  subject do
    lambda do
      a = Aliquot::Payment.new(token_string, shared_secret, merchant_id, keystring)
      a.process
    end
  end

  it 'accepts PAN_ONLY token' do
    @payment = AliquotPay.payment
    is_expected.to be_truthy
  end

  it 'accepts CRYPTOGRAM_3DS token without eciIndicator' do
    @payment = AliquotPay.payment(auth_method: :CRYPTOGRAM_3DS)
    @payment['paymentMethodDetails'].delete('eciIndicator')

    is_expected.to be_truthy
  end

  it 'rejects expired token' do
    @payment = AliquotPay.payment(expiration: ((Time.now.to_f - 1) * 1000).round.to_s)
    is_expected.to raise_error(Aliquot::ExpiredException)
  end

  it 'it fails validation on invalid merchant_id' do
    @payment = AliquotPay.payment
    a = Aliquot::Payment.new(token_string, shared_secret, 'incorrect', keystring)

    expect { a.process }.to raise_error(Aliquot::InvalidSignatureError)
  end

  it 'rejects invalid signature' do
    @payment = AliquotPay.payment
    sig = AliquotPay.sign(key, OpenSSL::Random.random_bytes(256))
    token['signature'] = sig
    a = Aliquot::Payment.new(token_string, shared_secret, merchant_id, keystring)

    expect { a.process }.to raise_error(Aliquot::InvalidSignatureError)
  end
end
