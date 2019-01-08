require 'aliquot-pay'

require 'json'

describe Aliquot::Payment do
  let(:token) { AliquotPay.generate_token(@payment, key, recipient) }
  let(:token_string) { JSON.unparse(token) }
  let(:shared_secret) { extract_shared_secret(token, recipient) }

  it 'decrypts successfully' do
    @payment = AliquotPay.payment
    a = Aliquot::Payment.new(token_string, shared_secret, merchant_id, signing_keys: keystring)
    a.process
  end

  it 'rejects expired payment' do
    @payment = AliquotPay.payment
    exp_time = (Time.now.to_f - 20).round.to_s
    @payment[:messageExpiration] = exp_time

    a = Aliquot::Payment.new(token_string, shared_secret, merchant_id, signing_keys: keystring)

    expect { a.process }.to raise_error(Aliquot::TokenExpiredError)
  end

  it 'rejects invalid token JSON gracefully' do
    @payment = AliquotPay.payment
    block = proc do
      Aliquot::Payment.new('invalid JSON', shared_secret, merchant_id, signing_keys: keystring)
    end

    expect(&block).to raise_error(Aliquot::InputError, /token JSON invalid, .+/)
  end

  it 'rejects invalid encryptedMessage JSON gracefully' do
    message = AliquotPay.encrypt('Invalid JSON', recipient)
    token = AliquotPay.generate_token(nil, key, recipient, JSON.unparse(message))
    shared_secret = extract_shared_secret(token, recipient)

    a = Aliquot::Payment.new(JSON.unparse(token), shared_secret, merchant_id, signing_keys: keystring)

    expect { a.process } .to raise_error(Aliquot::InputError, /encryptedMessage JSON invalid, /)
  end

  it 'fails gracefully with invalid shared secret' do
    message = AliquotPay.encrypt('Invalid JSON', recipient)
    token = AliquotPay.generate_token(nil, key, recipient, JSON.unparse(message))

    a = Aliquot::Payment.new(JSON.unparse(token), 'invalid shared secret', merchant_id, signing_keys: keystring)

    expect { a.process } .to raise_error(Aliquot::InvalidSharedSecretError, /shared_secret must be base64/)
  end

  it 'catches invalid signedMessage JSON gracefully' do
    message = AliquotPay.encrypt('Invalid JSON', recipient)
    token = AliquotPay.generate_token(nil, key, recipient, JSON.unparse(message))
    shared_secret = extract_shared_secret(token, recipient)
    token[:signedMessage] = 'not valid JSON'

    block = proc do
      Aliquot::Payment.new(JSON.unparse(token), shared_secret, merchant_id, signing_keys: keystring)
    end

    expect(&block).to raise_error(Aliquot::ValidationError, /signedMessage must be valid JSON/)
  end

  # KSE: I can't figure out how to provoke an error the following cases
  it 'fails to derive keys gracefully'
  it 'handles decryption error succesfully'
end
