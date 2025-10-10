require './lib/aliquot.rb'

# token_string::  Google Pay token (JSON string)
# shared_secret:: Base64 encoded shared secret
# recipient_id::  Google Pay recipient ID ("<PREFIX e.g. merchant>:<SOMETHING>")

token_string = '{"signature":"MEUCIQCv9wMt6Majaj2z/Xwo1l3LTw4uO6XgoEnFyQUpPyGbFgIgexqZzXueFnv5gzgFfC1tJ03xSzc9FVF6ofC2PFHIaPc\u003d","intermediateSigningKey":{"signedKey":"{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE06EllelMOfX2JIKTLtnPD8Vk+G58RSbcEB1tGPDqfQ9bPSRyPj8M+vQvTx5os4KkOyz36r2DqxHPUF1SeFqDew\\u003d\\u003d\",\"keyExpiration\":\"1760682782875\"}","signatures":["MEUCIAmViRdKM0KG8exF/l7HZhmzCmqneDDfyyhMg3FzLampAiEAqqAOiVL04mWMXxkA8gfBgE5xl9yt5BnZyDyWUEhTfwQ\u003d"]},"protocolVersion":"ECv2","signedMessage":"{\"encryptedMessage\":\"2NR/pHklGCB7zMVTO+tZlN3AbegkHe7xNngNmrFVSmL48JvYpyVFe9m7A1ykYEhaYPw/G2XqGNLaXfonVQBBd3Y0LVjzpBB+VF0clJvRBDe1/OMLMpTLMYK4uVBVUnBBi5ApJZl1NcAkRq8yJ0xa1MLQA1V8alUKvxYOKdzPZ3C9XT7owUbqrN5zQoEGJLvfhd3ITT2AmH9U/c/bkN9WlImHPUba99RHpsr5JffL4QN3DiN8WhZVJuiExuOTl1cb/RE3Cc/44Y5zOJhdqx2dKgvCtvkRHaXOgeCRc88KAYtmyKJENp0T94SIgy0s50bOnoT09MBsvuqt5cYu6DqwvcLbu1l5Hc41IXaEj4qyenYuXdrmAKojawjW4u1oImzzMeLiPeAks+hrdRIZkGYnBqNTHYgMTiq9oSbi3Km1Ga/YDvmPd5d8M/MiMS2/ezNZjbVff3BWPecwgkkojhn4vDFDnHhc4bm/SuFHZjy1J048O82FHND8wdMq2dmyc9mHe/PvyiIbBWdkE8DuuAXH8BF+opsQ3S0kX3ZIaOVj8iatii6Q\",\"ephemeralPublicKey\":\"BBeZH5HONy84nyAX0GdoJ8gAkSS+UOGiJ4LLn+MqNboQQl+Qm9y3PvXTcQbcKDIevyrVJVR25N46DudzDNaX2Xc\\u003d\",\"tag\":\"vaB4CSA01FIn6XqUEp48A6J6B99cKE7rNLYGAdiYYPE\\u003d\"}"}'
shared_secret = 'vi8EQG2PL+HpaVWZoji4DE+sc+ziS962rbD8gMmw3P4='
recipient_id =  'gateway:epay'

a = Aliquot::Payment.new(token_string, shared_secret, recipient_id)
a.process