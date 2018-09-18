require 'spec_helper'

describe Aliquot::Validator::TokenSchema do
  before(:each) do
    @token = JSON.parse(TOKEN)
  end
  context 'rejects invalid signature' do
    [
      ['Not a signature', /signature[^\w]+must be Base64/],
      ['',                /signature[^\w]+must be filled/],
    ].each do |sig, msg|
      it "when sig is '#{sig}'" do
        @token['signature'] = sig
        a = Aliquot::Payment.new(JSON.unparse(@token), SHARED_SECRET_B64, RECIPIENT_ID)
        expect { a.process }.to raise_error(Aliquot::Validator::Error, msg)
      end
    end
  end

  it 'rejects invalid protocolversion' do
    @token['protocolVersion'] = ''
    a = Aliquot::Payment.new(JSON.unparse(@token), SHARED_SECRET_B64, RECIPIENT_ID)
    expect { a.process }.to raise_error(Aliquot::Validator::Error, /protocolVersion[^\w]+must be filled/)
  end

  context 'rejects invalid signedMessage' do
    [
      [112,          /signedMessage[^\w]+must be a string/],
      ['not JSON',   /signedMessage[^\w]+must be valid JSON/],
    ].each do |sig, msg|
      it "when message is '#{sig}'" do
        @token['signedMessage'] = sig
        a = Aliquot::Payment.new(JSON.unparse(@token), SHARED_SECRET_B64, RECIPIENT_ID)
        expect { a.process }.to raise_error(Aliquot::Validator::Error, msg)
      end
    end
  end
end

describe Aliquot::Validator::SignedMessageSchema do
  before(:each) do
    @a = Aliquot::Payment.new(TOKEN, SHARED_SECRET_B64, RECIPIENT_ID)
  end

  context 'rejects invalid encryptedMessage' do
    [
      [112,          /encryptedMessage[^\w]+must be a string/],
      ['not Base64', /encryptedMessage[^\w]+must be Base64/],
    ].each do |msg, err|
      it "when msg is '#{msg}'" do
        dbl = double(signed_message: mod_sm_s(encryptedMessage: msg))
        expect(@a).to receive(:build_token).and_return(dbl)
        expect { @a.process }.to raise_error(Aliquot::Validator::Error, err)
      end
    end
  end

  context 'ephemeralPublicKey' do
    [
      [112,          /ephemeralPublicKey[^\w]+must be a string/],
      ['not Base64', /ephemeralPublicKey[^\w]+must be Base64/],
    ].each do |msg, err|
      it "is rejected when: '#{msg}'" do
        dbl = double(signed_message: mod_sm_s(ephemeralPublicKey: msg))
        expect(@a).to receive(:build_token).and_return(dbl)
        expect { @a.process }.to raise_error(Aliquot::Validator::Error, err)
      end
    end
  end

  context 'rejects invalid tag' do
    [
      [112,          /tag[^\w]+must be a string/],
      ['not Base64', /tag[^\w]+must be Base64/],
    ].each do |msg, err|
      it "is rejected when: '#{msg}'" do
        dbl = double(signed_message: mod_sm_s(tag: msg))
        expect(@a).to receive(:build_token).and_return(dbl)
        expect { @a.process }.to raise_error(Aliquot::Validator::Error, err)
      end
    end
  end
end

describe Aliquot::Validator::EncryptedMessage do
  before(:each) do
    @a = Aliquot::Payment.new(TOKEN, SHARED_SECRET_B64, RECIPIENT_ID)
  end

  context 'messageExpiration' do
    [
      [112,            /messageExpiration[^\w]+must be a string/],
      ['notintstring', /messageExpiration[^\w]+must be string encoded integer/],
    ].each do |msg, err|
      it "is rejected when: '#{msg}'" do
        json = mod_em(messageExpiration: msg)
        expect(@a).to receive(:decrypt).and_return(json)
        expect { @a.process }.to raise_error(Aliquot::Validator::Error, err)
      end
    end
  end

  it 'rejects invalid messageId' do
    json = mod_em(messageId: 112)
    expect(@a).to receive(:decrypt).and_return(json)
    expect { @a.process }.to raise_error(Aliquot::Validator::Error, /messageId[^\w]+must be a string/)
  end

  context 'paymentMethod' do
    [
      [112,        /paymentMethod[^\w]+must be a string/],
      ['not CARD', /paymentMethod[^\w]+must be equal to CARD/],
    ].each do |msg, err|
      it "is rejected when: '#{msg}'" do
        json = mod_em(paymentMethod: msg)
        expect(@a).to receive(:decrypt).and_return(json)
        expect { @a.process }.to raise_error(Aliquot::Validator::Error, err)
      end
    end
  end

  it 'rejects missing paymentMethodDetails' do
    json = mod_em([])
    json.delete('paymentMethodDetails')
    expect(@a).to receive(:decrypt).and_return(json)
    expect { @a.process }.to raise_error(Aliquot::Validator::Error, /paymentMethodDetails[^\w]+is missing/)
  end
end

describe Aliquot::Validator::PaymentMethodDetails do
  before(:each) do
    @a = Aliquot::Payment.new(TOKEN, SHARED_SECRET_B64, RECIPIENT_ID)
  end

  context 'pan' do
    [
      [112,            /pan[^\w]+must be a pan/],
      ['notintstring', /pan[^\w]+must be a pan/],
      [nil,            /pan[^\w]+must be filled/],
    ].each do |msg, err|
      it "is rejected when: '#{msg}'" do
        json = mod_em([:paymentMethodDetails, :pan] => msg)
        expect(@a).to receive(:decrypt).and_return(json)
        expect { @a.process }.to raise_error(Aliquot::Validator::Error, err)
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
        json = mod_em([:paymentMethodDetails, :expirationMonth] => msg)
        expect(@a).to receive(:decrypt).and_return(json)
        expect { @a.process }.to raise_error(Aliquot::Validator::Error, err)
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
        json = mod_em([:paymentMethodDetails, :expirationYear] => msg)
        expect(@a).to receive(:decrypt).and_return(json)
        expect { @a.process }.to raise_error(Aliquot::Validator::Error, err)
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
        json = mod_em([:paymentMethodDetails, :authMethod] => msg)
        expect(@a).to receive(:decrypt).and_return(json)
        expect { @a.process }.to raise_error(Aliquot::Validator::Error, err)
      end
    end
  end

  it 'accepts ECI data when CRYPTOGRAM_3DS' do
    json = mod_em3([])
    expect(@a).to receive(:decrypt).and_return(json)
    expect(@a).to receive(:expired?).and_return(false)
    @a.process
  end

  it 'accepts missing eciIndicator when CRYPTOGRAM_3DS' do
    json = mod_em3([:paymentMethodDetails, :eciIndicator] => nil)
    delete(json, [:paymentMethodDetails, :eciIndicator])
    expect(@a).to receive(:decrypt).and_return(json)
    expect(@a).to receive(:expired?).and_return(false)
    @a.process
    end

  it 'rejects ECI data when CARD' do
    json = mod_em3([:paymentMethodDetails, :authMethod] => 'PAN_ONLY')
    expect(@a).to receive(:decrypt).and_return(json)
    expect { @a.process }.to raise_error(Aliquot::Validator::Error, /authMethodCard.*omitted when PAN_ONLY/)
  end

  it 'rejects invalid ECI indicator' do
    json = mod_em3([:paymentMethodDetails, :eciIndicator] => 'not an ECI')
    expect(@a).to receive(:decrypt).and_return(json)
    expect { @a.process }.to raise_error(Aliquot::Validator::Error, /eciIndicator must be an ECI/)
  end

  it 'rejects invalid cryptogram' do
    json = mod_em3([:paymentMethodDetails, :cryptogram] => 124)
    expect(@a).to receive(:decrypt).and_return(json)
    expect { @a.process }.to raise_error(Aliquot::Validator::Error, /cryptogram must be a string/)
  end
end
