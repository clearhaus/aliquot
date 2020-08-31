module Aliquot
  # Base class for all errors thrown in Aliquot
  class Error < StandardError; end

  # Error in the input
  class InputError < Error; end

  # Errors in decryption. Might not be possible to provoke
  class DecryptionError < Error; end

  # When key derivation fails. Might not be possible to provoke
  class KeyDerivationError < Error; end

  # Thrown if the token is expired
  class TokenExpiredError < Error; end

  # Thrown if the signature is invalid
  class InvalidSignatureError < Error; end

  # Thrown if the MAC is invalid
  class InvalidMacError < Error; end

  # Thrown if there was an error validating the input data
  class ValidationError < Error; end

  # Thrown if JSON is invalid.
  class FormatError < Error; end

  # When shared_secret is invalid
  class InvalidSharedSecretError < Error; end

  # When recipient_id is invalid
  class InvalidRecipientIDError < Error; end
end
