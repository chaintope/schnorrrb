require_relative 'mu_sig/session'

module Schnorr

  # https://github.com/ElementsProject/secp256k1-zkp/blob/secp256k1-zkp/src/modules/musig/musig.md
  module MuSig

    # SHA256("MuSig coefficient")
    TAG = ['74894a2bec01af68225002cae9b0430ab63151ede5d31f641791976c7140b57b'].pack('H*')

    module_function

    # Computes ell = SHA256(pk[0], ..., pk[np-1])
    # @param public_keys (Array[String]) The set of public keys with binary format.
    # @return (String) ell
    def compute_ell(public_keys)
      Digest::SHA256.digest(public_keys.join)
    end

    # Combine public keys.
    # @param public_keys (Array[String]) The set of public keys with binary format.
    # @return (String) a combined public key point with binary format.
    def pubkey_combine(public_keys, ell: nil)
      ell = compute_ell(public_keys) unless ell
      points = public_keys.map.with_index do |p, idx|
        xi = ECDSA::Format::PointOctetString.decode(p, ECDSA::Group::Secp256k1)
        xi.multiply_by_scalar(coefficient(ell, idx))
      end
      sum = points.inject(:+)
      ECDSA::Format::PointOctetString.encode(sum, compression: true)
    end

    # Computes MuSig coefficient SHA256(TAG || TAG || ++ell++ || ++idx++).
    # @param ell (String) a ell with binary format.
    # @param idx (Integer) an index of public key.
    # @return (Integer) coefficient value.
    def coefficient(ell, idx)
      field = ECDSA::PrimeField.new(ECDSA::Group::Secp256k1.order)
      field.mod(Digest::SHA256.digest(TAG + TAG + ell + [idx].pack('I*')).unpack('H*').first.to_i(16))
    end

    # signer starts the session.
    # @param session_id (String) if ++session_id++ is nil, generate new one.
    # @param private_key (Integer) a private key.
    # @param message (String) a message for sign with binary format.
    # @param combined_pubkey (String) combined public key with binary format.
    # @param ell (String) ell with binary format.
    # @param index (Integer) public key index.
    # @return (Schnorr::MuSig::Session) session object.
    def session_initialize(session_id, private_key, message, combined_pubkey, ell, index)
      raise ArgumentError, 'session_id must be 32 bytes.' if session_id && session_id.bytesize != 32
      raise ArgumentError, 'message must be 32 bytes.' unless message.bytesize == 32
      raise ArgumentError, 'combined_pubkey must be 33 bytes.' unless combined_pubkey.bytesize == 33
      raise ArgumentError, 'ell must be 32 bytes.' unless ell.bytesize == 32
      secret = ECDSA::Format::IntegerOctetString.encode(private_key, ECDSA::Group::Secp256k1.byte_length)

      field = ECDSA::PrimeField.new(ECDSA::Group::Secp256k1.order)
      session = Schnorr::MuSig::Session.new(session_id)
      coefficient = coefficient(ell, index)
      session.secret_key = field.mod(private_key * coefficient)
      session.secret_nonce = Digest::SHA256.digest(session.id + message + combined_pubkey + secret).unpack('H*').first.to_i(16)
      raise ArgumentError, 'secret nonce must be an integer in the ragen 1..n-1' unless field.include?(session.secret_nonce)
      point_r = ECDSA::Group::Secp256k1.new_point(session.secret_nonce)
      session.nonce = ECDSA::Format::PointOctetString.encode(point_r, compression: true)
      session.commitment = Digest::SHA256.digest(session.nonce)
      session
    end

    private_class_method :coefficient

  end

end