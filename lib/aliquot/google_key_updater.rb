require 'singleton'

module Aliquot
  # Class responsible for updating the google signing keys.
  class GoogleKeyUpdater
    include Singleton

    attr_reader :keys

    def initialize
      puts('Starting Google Key Updater')
      #Thread.current[:keys] = keys
    end

    def self.update_keys
      '{"keys":[{"keyValue":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIsFro6K+IUxRr4yFTOTO+kFCCEvHo7B9IOMLxah6c977oFzX\/beObH4a9OfosMHmft3JJZ6B3xpjIb8kduK4\/A==","protocolVersion":"ECv1"},{"keyValue":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGnJ7Yo1sX9b4kr4Aa5uq58JRQfzD8bIJXw7WXaap\/hVE+PnFxvjx4nVxt79SdRuUVeu++HZD0cGAv4IOznc96w==","protocolVersion":"ECv2","keyExpiration":"2154841200000"},{"keyValue":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGnJ7Yo1sX9b4kr4Aa5uq58JRQfzD8bIJXw7WXaap\/hVE+PnFxvjx4nVxt79SdRuUVeu++HZD0cGAv4IOznc96w==","protocolVersion":"ECv2SigningOnly","keyExpiration":"2154841200000"}]}'
    end

    def updater
      loop do
        sleep 2
        puts('Sleeping')
      end
    end
  end
end
