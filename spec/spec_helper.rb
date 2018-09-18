TOKEN = '{"signature":"MEUCIQCgK4uhCD5z0JmjBv0US3eL812PFzbWSHq9zLt8R1uJcAIgVOt7jax9fEqsxvQoS8XM+N83cznu+QpCWqvsV4yvixc=","protocolVersion":"ECv1","signedMessage":"{\"encryptedMessage\":\"veVA1ij89B2CcfZjGufSP/B+l6hLtZ384v62T+QBBt3sxUFERoFtbFqQrpH2nqyAPj46NclX+h1udvdISPgJf7YslxNdiTU2+rbfBNFE3CXPdRQrpdQaE2Kr/aZuMCmcQKGZmgnScvdoWyvLlTO9vf6rNBDNbWIngJMVFFhJgYrJzwpGs0gmPpLvVfudgVZ8gxXE/oBbS5X9Rqc0Faei6g79W4hcHQyY9lIssQiMa1HtdCIseV/l5LCjYqZC1Adoht50inS655GRDktmDYhMQpK/uUe0ozTuBa3RCWjwZ9AK0TdRYQlBFNpHjO8GHM1mYmtfVg0nH8JQ13ubOHH5pynyU8UhoXOBHtKHPlEqX6pDhoQVrioBOsahoZmGTYQ4ae+U2nV97NmBQ1bxu2Mp3CEMQzv9Z58A7N0fehTsjlIMB7L8QROo7wiWm5c\\u003d\",\"ephemeralPublicKey\":\"BOEBIE35UiNOTBHnJ7N4yQ9k6f/FbiCSq7qk+elnLRyFZp1ttAbfzItjwlYRA7mRi/c17amrW2z9KKZF7jMtkpE\\u003d\",\"tag\":\"hFM0EAz+VMoMwPlZAzDoxrDcDeZDX1OMleBxDq5LFVo\\u003d\"}"}'.freeze

SHARED_SECRET_B64 = 'gsqQQcQ81LHdNyO4IfOROtCi2/ZNnmVxfScMT70ux+A='.freeze
RECIPIENT_ID = 'merchant:12345678901234567890'.freeze

ENCRYPTED_MESSAGE = '
  {
    "messageExpiration": "1536844787252",
    "messageId": "SOME ID",
    "paymentMethod": "CARD",
    "paymentMethodDetails": {
      "expirationYear": 2023,
      "expirationMonth": 12,
      "pan": "4111111111111111",
      "authMethod": "PAN_ONLY"
    }
  }'.freeze

ENCRYPTED_MESSAGE_3DS = '
  {
    "messageExpiration": "1536844787252",
    "messageId": "SOME ID",
    "paymentMethod": "CARD",
    "paymentMethodDetails": {
      "expirationYear":  2023,
      "expirationMonth": 12,
      "pan":             "4111111111111111",
      "authMethod":      "CRYPTOGRAM_3DS",
      "cryptogram":      "Example cryptogram",
      "eciIndicator":    "05"
    }
  }'.freeze

SIGNED_MESSAGE = '
  {
    "encryptedMessage": "veVA1ij89B2CcfZjGufSP/B+l6hLtZ384v62T+QBBt3sxUFERoFtbFqQrpH2nqyAPj46NclX+h1udvdISPgJf7YslxNdiTU2+rbfBNFE3CXPdRQrpdQaE2Kr/aZuMCmcQKGZmgnScvdoWyvLlTO9vf6rNBDNbWIngJMVFFhJgYrJzwpGs0gmPpLvVfudgVZ8gxXE/oBbS5X9Rqc0Faei6g79W4hcHQyY9lIssQiMa1HtdCIseV/l5LCjYqZC1Adoht50inS655GRDktmDYhMQpK/uUe0ozTuBa3RCWjwZ9AK0TdRYQlBFNpHjO8GHM1mYmtfVg0nH8JQ13ubOHH5pynyU8UhoXOBHtKHPlEqX6pDhoQVrioBOsahoZmGTYQ4ae+U2nV97NmBQ1bxu2Mp3CEMQzv9Z58A7N0fehTsjlIMB7L8QROo7wiWm5c=",
    "ephemeralPublicKey": "BOEBIE35UiNOTBHnJ7N4yQ9k6f/FbiCSq7qk+elnLRyFZp1ttAbfzItjwlYRA7mRi/c17amrW2z9KKZF7jMtkpE=",
    "tag": "hFM0EAz+VMoMwPlZAzDoxrDcDeZDX1OMleBxDq5LFVo="
  }'.freeze

def recursive_fetch(map, keys)
  val = map
  keys.each do |sym|
    val = val[sym.to_s]
  end
  val
end

def mod_json(map, mods)
  json = JSON.parse(map)

  mods.each do |k, v|
    if k.is_a?(Symbol)
      json[k.to_s] = v
    elsif k.is_a?(Array)
      val = recursive_fetch(json, k.slice(0, k.length - 1))
      val[k.last.to_s] = v
    end
  end

  json
end

def delete(map, keys)
  val = recursive_fetch(map, keys.slice(0, keys.length - 1))
  val.delete(keys.last.to_s)
end

def mod_token(mods)
  mod_json(TOKEN, mods)
end

def mod_token_s(mods)
  JSON.unparse(mod_json(TOKEN, mods))
end

def mod_sm(mods)
  mod_json(SIGNED_MESSAGE, mods)
end

def mod_sm_s(mods)
  JSON.unparse(mod_json(SIGNED_MESSAGE, mods))
end

def mod_em(mods)
  mod_json(ENCRYPTED_MESSAGE, mods)
end

def mod_em_s(mods)
  JSON.unparse(mod_json(ENCRYPTED_MESSAGE, mods))
end

def mod_em3(mods)
  mod_json(ENCRYPTED_MESSAGE_3DS, mods)
end

def mod_em3_s(mods)
  JSON.unparse(mod_json(ENCRYPTED_MESSAGE_3DS, mods))
end
