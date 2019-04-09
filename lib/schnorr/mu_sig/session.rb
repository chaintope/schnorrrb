module Schnorr
  module MuSig
    class Session

      attr_reader :id               # binary
      attr_accessor :secret_key     # Integer
      attr_accessor :secret_nonce   # Integer
      attr_accessor :nonce          # binary
      attr_accessor :commitment     # binary
      attr_accessor :nonce_negate   # Boolean

      def initialize(session_id = SecureRandom.random_bytes(32))
        @id = session_id
        @nonce_negate = false
      end

      # combine nonce
      # @param nonces (Array[String]) an array of other signer's nonce with binary format.
      # @return (String) combined nonce with binary format.
      def nonce_combine(nonces)
        points = ([nonce]+ nonces).map.with_index {|n, index|ECDSA::Format::PointOctetString.decode(n, ECDSA::Group::Secp256k1)}
        r_point = points.inject(:+)
        unless ECDSA::PrimeField.jacobi(r_point.y, ECDSA::Group::Secp256k1.field.prime) == 1
          self.nonce_negate = true
          r_point = r_point.negate
        end
        ECDSA::Format::PointOctetString.encode(r_point, compression: true)
      end

    end
  end
end