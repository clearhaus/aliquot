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

    expect { a.process }.to raise_error(Aliquot::ExpiredException)
  end
end
