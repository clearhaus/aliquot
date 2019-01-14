require 'aliquot-pay'

require 'json'
require 'openssl'

describe Aliquot::Payment do
  let(:token) { AliquotPay.generate_token_ecv1(@payment, key, recipient) }
  let(:token_string) { token.to_json }
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
    message = AliquotPay.encrypt('Invalid JSON', recipient, :ECv1)
    token = AliquotPay.generate_token_ecv1(nil, key, recipient, message.to_json)
    shared_secret = extract_shared_secret(token, recipient)

    a = Aliquot::Payment.new(token.to_json, shared_secret, merchant_id, signing_keys: keystring)

    expect { a.process } .to raise_error(Aliquot::InputError, /encryptedMessage JSON invalid, /)
  end

  it 'fails gracefully with invalid shared secret' do
    message = AliquotPay.encrypt('Invalid JSON', recipient, :ECv1)
    token = AliquotPay.generate_token_ecv1(nil, key, recipient, message.to_json)

    a = Aliquot::Payment.new(token.to_json, 'invalid shared secret', merchant_id, signing_keys: keystring)

    expect { a.process } .to raise_error(Aliquot::InvalidSharedSecretError, /shared_secret must be base64/)
  end

  it 'catches invalid signedMessage JSON gracefully' do
    message = AliquotPay.encrypt('Invalid JSON', recipient, :ECv1)
    token = AliquotPay.generate_token_ecv1(nil, key, recipient, message.to_json)
    shared_secret = extract_shared_secret(token, recipient)
    token[:signedMessage] = 'not valid JSON'

    block = proc do
      Aliquot::Payment.new(token.to_json, shared_secret, merchant_id, signing_keys: keystring)
    end

    expect(&block).to raise_error(Aliquot::ValidationError, /signedMessage must be valid JSON/)
  end

  it 'handles decryption error succesfully' do
    name = OpenSSL::ASN1::PrintableString.new('not a signature')
    asn1 = OpenSSL::ASN1::Sequence.new([name])
    der  = asn1.to_der

    @payment = AliquotPay.payment
    token['signature'] = Base64.strict_encode64(der)
    a = Aliquot::Payment.new(token_string, shared_secret, merchant_id, signing_keys: keystring)
    expect { a.process }.to raise_error(Aliquot::InvalidSignatureError, /nested asn1 error/)
  end

  # KSE: I can't figure out how to provoke an error the following cases
  it 'fails to derive keys gracefully'
end

describe Aliquot::Payment do
  let(:token) { AliquotPay.generate_token_ecv2(payment, key_ecv2, intermediate_key, recipient) }
  let(:token_string) { token.to_json }
  let(:shared_secret) { extract_shared_secret(token, recipient) }
  let(:payment) { AliquotPay.payment }

  context 'ECv2' do
    it 'validates ECv2 token' do
      a = Aliquot::Payment.new(token_string, shared_secret, merchant_id, signing_keys: keystring)
      a.process
    end

    it 'requires intermediateSigningKey when ECv2' do
      token.delete('intermediateSigningKey')
      block = proc do
        Aliquot::Payment.new(token_string, shared_secret, merchant_id, signing_keys: keystring)
      end
      expect(&block).to raise_error(Aliquot::ValidationError, /intermediateSigningKey must be filled/)
    end

    it 'requires intermediateSigningKey valid when ECv2' do
      token['intermediateSigningKey'] = { 'random' => 'values' }
      block = proc do
        Aliquot::Payment.new(token_string, shared_secret, merchant_id, signing_keys: keystring)
      end
      expect(&block).to raise_error(Aliquot::ValidationError, /signedKey is missing.+signatures is missing/)
    end

    it 'rejects invalid signedKey JSON' do
      token['intermediateSigningKey']['signedKey'] = 'Invalid JSON'
      block = proc do
        Aliquot::Payment.new(token_string, shared_secret, merchant_id, signing_keys: keystring)
      end
      expect(&block).to raise_error(Aliquot::ValidationError, /signedKey must be valid JSON/)
    end

    it 'rejects invalid intermediate signatures' do
      fake_sig = Base64.strict_encode64(Random.new.bytes(70))
      token['intermediateSigningKey']['signatures'] = [fake_sig]
      block = proc do
        Aliquot::Payment.new(token_string, shared_secret, merchant_id, signing_keys: keystring)
      end

      expect(&block).to raise_error(Aliquot::ValidationError, /intermediateSigningKey.signatures.0 must be base64 encoded asn1 value/)
    end

    it 'rejects incorrect intermediate signatures' do
      extra_key = OpenSSL::PKey::EC.new('prime256v1').generate_key
      invalid_signature = AliquotPay.sign(extra_key, token['intermediateSigningKey']['signedKey'])

      token['intermediateSigningKey']['signatures'] = [invalid_signature]

      a = Aliquot::Payment.new(token_string, shared_secret, merchant_id, signing_keys: keystring)
      expect { a.process }.to raise_error(Aliquot::InvalidSignatureError, /intermediate not signed/)
    end

    it 'ignores incorrect intermediate signatures' do
      extra_key = OpenSSL::PKey::EC.new('prime256v1').generate_key
      invalid_signature = AliquotPay.sign(extra_key, token['intermediateSigningKey']['signedKey'])

      token['intermediateSigningKey']['signatures'].push(invalid_signature)

      a = Aliquot::Payment.new(token_string, shared_secret, merchant_id, signing_keys: keystring)
      a.process
    end

    it 'rejects expired intermediate key' do
      expire_time = (Time.now.to_f - 600).round.to_s
      token = AliquotPay.generate_token_ecv2(payment, key_ecv2, intermediate_key, recipient, expire_time: expire_time)
      token_string = token.to_json
      shared_secret = extract_shared_secret(token, recipient)
      a = Aliquot::Payment.new(token_string, shared_secret, merchant_id, signing_keys: keystring)

      expect { a.process }.to raise_error(Aliquot::InvalidSignatureError, /intermediate certificate expired/)
    end
  end
end
