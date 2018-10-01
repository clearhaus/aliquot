module Aliquot
  class Error < StandardError; end
  class ExpiredException < Error; end
  class InvalidSignatureError < Error; end
  class InvalidMacError < Error; end
  class ValidationError < Error; end
end
