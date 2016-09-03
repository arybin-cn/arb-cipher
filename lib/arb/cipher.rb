require "arb/cipher/version"
require 'openssl'
require 'base64'

module Arb
  module Cipher
    class << self
      %w{encrypt decrypt}.each do |action|
        define_method action do |data,key,algorithm='AES-128-CBC'|
          cipher = OpenSSL::Cipher.new(algorithm)
        cipher.send action
        cipher.key=key
        cipher.update(data)+cipher.final
        end
      end
      define_method :encrypt64 do |*args|
        Base64.encode64(encrypt(*args)).chomp
      end
      define_method :decrypt64 do |data,*args|
        decrypt(Base64.decode64(data),*args)
      end
      def method_missing(name,*args,&block)
        OpenSSL::Cipher.send name,*args,&block
      end
      def respond_to_missing?(*args)
        OpenSSL::Cipher.respond_to? *args
      end
    end
  end
end
