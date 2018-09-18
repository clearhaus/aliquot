require 'spec_helper'

require 'aliquot'
require 'json'

describe Aliquot::Payment do
  it 'validates valid token' do
    a = Aliquot::Payment.new(TOKEN, SHARED_SECRET_B64, RECIPIENT_ID)
    expect(a).to receive(:expired?).and_return(false)
    a.process
  end

  it 'rejects expired token' do
    a = Aliquot::Payment.new(TOKEN, SHARED_SECRET_B64, RECIPIENT_ID)

    # Load example payload, set expire time to 1 minutes ago
    payload = mod_em(messageExpiration: ((Time.now.to_f * 1000).round - 1 * 60 * 1000).to_s)
    expect(a).to receive(:decrypt).and_return(payload)

    expect { a.process }.to raise_error(Aliquot::ExpiredException)
  end
end
