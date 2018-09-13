require 'spec_helper'

require 'aliquot'

describe Aliquot::Payment do
  it 'validates valid token' do
    a = Aliquot::Payment.new(TOKENSTRING, SHARED_SECRET_B64, RECIPIENT_ID)
    expect(a).to receive(:expired?).and_return(false)
    a.process
  end

  it 'rejects expired token' do
    a = Aliquot::Payment.new(TOKENSTRING, SHARED_SECRET_B64, RECIPIENT_ID)
    expect(a).to receive(:expired?).and_return(true)
    expect { a.process }.to raise_error(Aliquot::ExpiredException)
  end
end
