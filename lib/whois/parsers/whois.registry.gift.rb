require_relative 'whois.uniregistry.net'

module Whois
  class Parsers
    # The current IANA-listed WHOIS host for .GIFT uses the Uniregistry
    # response format.
    class WhoisRegistryGift < WhoisUniregistryNet
    end
  end
end
