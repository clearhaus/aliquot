require 'aliquot-pay'
require 'aliquot'

require 'json'
require 'openssl'

# Test that all `raise` errors are caught and handled gracefully.
# Ordered by occurrence of raise in the `payment.rb` source code.

shared_examples 'all protocol versions' do
  # CB: Not sure how to trigger this test as JSON.parse has changed since 2.3
  #     see https://clearhaus.slack.com/archives/C3LG75WE9/p1661940442665459
  it 'rejects invalid token JSON gracefully'

  it 'rejects invalid protocolVersion' do
    generator.token['protocolVersion'] = 'InvalidProtocolVersion'
    expect { subject.call }.to raise_error(Aliquot::Error, 'supported protocol versions are ECv1, ECv2')
  end

  # KSE: Don't know how to trigger this.
  it 'fails gracefully when deriving keys'

  it 'fails gracefully when MAC is invalid' do
    generator.tag = Base64.strict_encode64(Random.new.bytes(32))
    expect { subject.call }.to raise_error(Aliquot::InvalidMacError, 'MAC does not match')
  end

  # CB: Not sure how to trigger this test as JSON.parse has changed since 2.3
  #     see https://clearhaus.slack.com/archives/C3LG75WE9/p1661940442665459
  it 'rejects invalid encryptedMessage JSON gracefully'

  # KSE: Can this be triggered?
  it 'fails decryption gracefully'

  it 'rejects expired token' do
    generator.message_expiration = (Time.now.to_f - 20).round.to_s
    expect { subject.call }.to raise_error(Aliquot::TokenExpiredError, 'token is expired')
  end

  it 'rejects invalid recipient_id' do
    generator.recipient_id = 'Some invalid id'
    expect { subject.call }.to raise_error(Aliquot::InvalidRecipientIDError)
  end

  it 'rejects non-base64 shared_secret' do
    block = proc do
      Aliquot::Payment.new(generator.token.to_json,
                           'not base64',
                           generator.recipient_id,
                           signing_keys: generator.extract_root_signing_keys)
        .process
    end
    expect(&block).to raise_error(Aliquot::InvalidSharedSecretError, 'shared_secret must be base64')
  end

  it 'rejects shared_secret when not 32 bytes' do
    generator.shared_secret = 'not 32 bytes'
    expect { subject.call }.to raise_error(Aliquot::InvalidSharedSecretError, 'shared_secret must be 32 bytes when base64 decoded')
  end

  it 'rejects when signature of signedMessage does not match' do
    generator.signature = AliquotPay.new.build_signature
    expect { subject.call }.to raise_error(Aliquot::InvalidSignatureError, 'signature of signedMessage does not match')
  end

  it 'rejects when failing to verify signature' do
    name = OpenSSL::ASN1::PrintableString.new('not a signature')
    asn1 = OpenSSL::ASN1::Sequence.new([name])
    der  = asn1.to_der

    generator.signature = Base64.strict_encode64(der)
    expect { subject.call }.to raise_error(Aliquot::InvalidSignatureError, /\Aerror verifying signature,/)
  end
end

shared_examples 'only ECv2' do
  it 'rejects expired intermediateSigningKey' do
    generator.key_expiration = "#{Time.now.to_i - 1}000"
    expect { subject.call }.to raise_error(Aliquot::InvalidSignatureError, 'intermediate certificate is expired')
  end

  it 'rejects when no signature of intermediateKey is found' do
    generator.signatures = AliquotPay.new.build_signatures
    expect { subject.call }.to raise_error(Aliquot::InvalidSignatureError, 'no valid signature of intermediate key')
  end

  it 'allows invalid intermediate signatures to be present' do
    fake_signature = AliquotPay.new.build_signatures.first
    real_signature = generator.build_signatures.first

    generator.signatures = [fake_signature, real_signature]

    expect(token['intermediateSigningKey']['signatures']).to include(fake_signature)
    expect(token['intermediateSigningKey']['signatures']).to include(real_signature)

    expect { subject.call }.to_not raise_error
  end
end

describe Aliquot::Payment do
  let(:generator) { AliquotPay.new(protocol_version: :ECv1, type: :browser) }
  subject do
    -> do Aliquot::Payment.new(generator.token.to_json,
                               generator.shared_secret,
                               generator.recipient_id,
                               signing_keys: generator.extract_root_signing_keys)
            .process
    end
  end

  context 'ECv1' do
    context 'non-tokenized' do
      let(:generator) { AliquotPay.new(protocol_version: :ECv1, type: :browser) }
      let(:token) { generator.token }

      include_examples 'all protocol versions'
      it 'decrypts with PAN_ONLY' do
        expect { subject.call }.to_not raise_error
        expect(subject.call[:paymentMethodDetails]).to_not include('authMethod' => 'PAN_ONLY')
      end
    end
    context 'tokenized' do
      let(:generator) { AliquotPay.new(protocol_version: :ECv1, type: :app) }
      let(:token) { generator.token }

      include_examples 'all protocol versions'
      it 'decrypts with 3DS' do
        expect { subject.call }.to_not raise_error
        expect(subject.call[:paymentMethodDetails]).to include('authMethod' => '3DS')
      end
    end
  end

  context 'ECv2' do
    context 'non-tokenized' do
      let(:generator) { AliquotPay.new(protocol_version: :ECv2, type: :browser) }
      let(:token) { generator.token }

      include_examples 'all protocol versions'
      include_examples 'only ECv2'
      it 'decrypts' do
        expect { subject.call }.to_not raise_error
        expect(subject.call[:paymentMethodDetails]).to include('authMethod' => 'PAN_ONLY')
      end
    end
    context 'tokenized' do
      let(:generator) { AliquotPay.new(protocol_version: :ECv2, type: :app) }
      let(:token) { generator.token }

      include_examples 'all protocol versions'
      include_examples 'only ECv2'
      it 'decrypts' do
        expect { subject.call }.to_not raise_error
        expect(subject.call[:paymentMethodDetails]).to include('authMethod' => 'CRYPTOGRAM_3DS')
      end
    end
  end
end
