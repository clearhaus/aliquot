require 'json'

require 'aliquot-pay/util'

def extract_shared_secret(token, recipient)
  eph = JSON.parse(token['signedMessage'])['ephemeralPublicKey']
  bn = OpenSSL::BN.new(Base64.strict_decode64(eph), 2)
  group = OpenSSL::PKey::EC::Group.new('prime256v1')
  point = OpenSSL::PKey::EC::Point.new(group, bn)
  Base64.strict_encode64(AliquotPay::Util.generate_shared_secret(recipient, point))
end
