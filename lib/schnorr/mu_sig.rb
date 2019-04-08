module Schnorr

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
      sum = points.inject{|sum, i| sum + i}
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

    private_class_method :coefficient

  end

end