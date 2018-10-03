module Aliquot
  # Base class for all errors thrown in Aliquot
  class Error < StandardError; end

  # Thrown if the token is expired
  class ExpiredException < Error; end

  # Thrown if the signature is invalid
  class InvalidSignatureError < Error; end

  # Thrown if the MAC is invalid
  class InvalidMacError < Error; end

  # Thrown if there was an error validating the input data
  class ValidationError < Error; end
end
