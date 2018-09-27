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

def keystring
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

def extract_shared_secret(token, recipient)
  eph = JSON.parse(token['signedMessage'])['ephemeralPublicKey']
  bn = OpenSSL::BN.new(Base64.strict_decode64(eph), 2)
  group = OpenSSL::PKey::EC::Group.new('prime256v1')
  point = OpenSSL::PKey::EC::Point.new(group, bn)
  Base64.strict_encode64(AliquotPay::Util.generate_shared_secret(recipient, point))
end
