require 'json'

require 'aliquot-pay/util'

def recipient
  @recipient ||= OpenSSL::PKey::EC.new('prime256v1').generate_key
end

def merchant_id
  AliquotPay::DEFAULTS[:merchant_id]
end

def key
  @key ||= OpenSSL::PKey::EC.new('prime256v1').generate_key
end

def key_ecv2
  @key_ecv2 ||= OpenSSL::PKey::EC.new('prime256v1').generate_key
end

def intermediate_key
  @intermediate_key ||= OpenSSL::PKey::EC.new('prime256v1').generate_key
end

def keystring
  ecv1_public_key = OpenSSL::PKey::EC.new(key.group)
  ecv1_public_key.public_key = key.public_key

  ecv2_public_key = OpenSSL::PKey::EC.new(key_ecv2.group)
  ecv2_public_key.public_key = key_ecv2.public_key
  {
    'keys' => [
      {
        'keyValue'        => Base64.strict_encode64(ecv1_public_key.to_der),
        'protocolVersion' => 'ECv1',
      },
      {
        'keyValue'        => Base64.strict_encode64(ecv2_public_key.to_der),
        'protocolVersion' => 'ECv2',
      },
    ],
  }.to_json
end

def extract_shared_secret(token, recipient)
  eph = JSON.parse(token['signedMessage'])['ephemeralPublicKey']
  bn = OpenSSL::BN.new(Base64.strict_decode64(eph), 2)
  group = OpenSSL::PKey::EC::Group.new('prime256v1')
  point = OpenSSL::PKey::EC::Point.new(group, bn)
  Base64.strict_encode64(AliquotPay::Util.generate_shared_secret(recipient, point))
end
