module Schnorr

  module MuSig

    module_function

    # Computes ell = SHA256(pk[0], ..., pk[np-1])
    # @param public_keys (Array[String]) The set of public keys with binary format.
    # @return (String) ell
    def compute_ell(*public_keys)
      Digest::SHA256.digest(public_keys.join)
    end

  end

end