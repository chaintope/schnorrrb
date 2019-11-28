module Schnorr
  module MuSig
    class Session

      attr_reader :id               # binary
      attr_accessor :secret_key     # Integer
      attr_accessor :secret_nonce   # Integer
      attr_accessor :nonce          # binary
      attr_accessor :nonce_negate   # Boolean

      def initialize(session_id = SecureRandom.random_bytes(32))
        @id = session_id
        @nonce_negate = false
      end

      def nonce_negate?
        @nonce_negate
      end

      # Get nonce commitment
      # @return [String] commitment with binary format.
      def commitment
        Digest::SHA256.digest(nonce)
      end

      # Combine nonce
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

      # Compute partial signature.
      # @param message (String) a message for signature with binary format.
      # @param combined_nonce (String) combined nonce with binary format.
      # @param combined_pubkey (String) combined public key with binary format.
      # @return (Integer) a partial signature.
      def partial_sign(message, combined_nonce, combined_pubkey)
        field = ECDSA::PrimeField.new(ECDSA::Group::Secp256k1.order)
        point_r = ECDSA::Format::PointOctetString.decode(combined_nonce, ECDSA::Group::Secp256k1)
        point_p = ECDSA::Format::PointOctetString.decode(combined_pubkey, ECDSA::Group::Secp256k1)
        e = Schnorr.create_challenge(point_r.x, point_p, message, field, point_r.group)
        k = secret_nonce
        k = 0 - k if nonce_negate?
        field.mod(secret_key * e + k)
      end

    end
  end
end