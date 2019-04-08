module Schnorr
  module MuSig
    class Session

      attr_reader :id

      attr_accessor :secret_key
      attr_accessor :secret_nonce
      attr_accessor :nonce
      attr_accessor :commitment

      def initialize(session_id = SecureRandom.random_bytes(32))
        @id = session_id
      end

    end
  end
end