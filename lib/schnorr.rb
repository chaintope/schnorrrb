require 'ecdsa'
require_relative 'schnorr/signature'

module Schnorr

  module_function

  # Generate schnorr signature.
  # @param group (ECDSA::Group) The curve that is being used.
  # @param message (String) A message to be signed with binary format.
  # @param private_key (Integer) The private key.
  # (The number of times to add the generator point to itself to get the public key.)
  # @return (Schnorr::Signature)
  def sign(message, private_key, group: ECDSA::Group::Secp256k1)
    secret = ECDSA::Format::IntegerOctetString.encode(private_key, group.byte_length)
    field = ECDSA::PrimeField.new(group.order)
    k = field.mod(ECDSA::Format::IntegerOctetString.decode(Digest::SHA256.digest(secret + message)))
    raise 'Creation of signature failed. k is zero' if k.zero?

    r_point = group.new_point(k)
    unless ECDSA::PrimeField.jacobi(r_point.y, group.field.prime) == 1
      k = group.order - k
    end

    r = ECDSA::Format::IntegerOctetString.encode(r_point.x, group.byte_length)
    pubkey = ECDSA::Format::PointOctetString.encode(group.new_point(private_key), compression: true)
    e = field.mod(ECDSA.normalize_digest(Digest::SHA256.digest(r + pubkey + message), group.bit_length))
    Schnorr::Signature.new(r_point.x, field.mod(k + e * private_key))
  end

  # Verifies the given {Signature} and returns true if it is valid.
  # @param digest (String or Integer)
  # @param public_key (EDCDSA::Point)
  # @param signature (Schnorr::Signature)
  def valid_sig?(digest, public_key, signature)

  end

end
