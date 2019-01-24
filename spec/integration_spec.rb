require 'aliquot'
require 'aliquot/payment'

require 'aliquot-pay'

shared_examples 'common integration tests' do
  context 'invokes' do
    it Aliquot::Validator::Token do
      e = StandardError.new('stub method')
      allow(Aliquot::Validator::Token).to receive(:new).and_raise(e)

      is_expected.to raise_error(e)

      expect(Aliquot::Validator::Token).to have_received(:new).with(token)
    end

    it Aliquot::Validator::SignedMessage do
      e = StandardError.new('stub method')
      allow(Aliquot::Validator::SignedMessage).to receive(:new).and_raise(e)

      is_expected.to raise_error(e)

      expect(Aliquot::Validator::SignedMessage).to have_received(:new).with(generator.build_signed_message)
    end

    it Aliquot::Validator::EncryptedMessageValidator do
      e = StandardError.new('stub method')
      allow(Aliquot::Validator::EncryptedMessageValidator).to receive(:new).and_raise(e)

      is_expected.to raise_error(e)

      expect(Aliquot::Validator::EncryptedMessageValidator).to have_received(:new).with(generator.build_cleartext_message)
    end
  end
end

describe Aliquot::Payment do
  let (:token) { generator.token }

  subject do
    -> do Aliquot::Payment.new(generator.token.to_json,
                               generator.shared_secret,
                               generator.merchant_id,
                               signing_keys: generator.extract_root_signing_keys)
        .process
    end
  end

  context :ECv1 do
    let (:generator) { AliquotPay.new(:ECv1) }

    include_examples 'common integration tests'
  end

  context :ECv2 do
    let (:generator) { AliquotPay.new(:ECv2) }

    include_examples 'common integration tests'

    it Aliquot::Validator::SignedKeyValidator do
      e = StandardError.new('stub method')
      allow(Aliquot::Validator::SignedKeyValidator).to receive(:new).and_raise(e)

      is_expected.to raise_error(e)

      expect(Aliquot::Validator::SignedKeyValidator).to have_received(:new).with(generator.build_signed_key)
    end
  end
end
