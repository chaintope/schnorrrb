require 'ecdsa'
require_relative 'schnorr/signature'

module Schnorr

  module_function

  # Generate schnorr signature.
  # @param message (String) A message to be signed with binary format.
  # @param private_key (Integer) The private key.
  # (The number of times to add the generator point to itself to get the public key.)
  # @param group (ECDSA::Group) The curve that is being used.
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

    e = create_challenge(r_point.x, group.new_point(private_key), message, field, group)

    Schnorr::Signature.new(r_point.x, field.mod(k + e * private_key))
  end

  # Verifies the given {Signature} and returns true if it is valid.
  # @param message (String) A message to be signed with binary format.
  # @param public_key (String) The public key with binary format.
  # @param signature (String) The signature with binary format.
  # @param group (ECDSA::Group) The curve that is being used.
  # @return (Boolean) whether signature is valid.
  def valid_sig?(message, public_key, signature, group: ECDSA::Group::Secp256k1)
    check_sig!(message, public_key, signature, group)
  rescue InvalidSignatureError, ECDSA::Format::DecodeError
    false
  end

  # Verifies the given {Signature} and raises an {InvalidSignatureError} if it is invalid.
  # @param message (String) A message to be signed with binary format.
  # @param public_key (String) The public key with binary format.
  # @param signature (String) The signature with binary format.
  # @param group (ECDSA::Group) The curve that is being used.
  # @return true
  def check_sig!(message, public_key, signature, group)
    sig = Schnorr::Signature.decode(signature)
    pubkey = ECDSA::Format::PointOctetString.decode(public_key, group)
    field = group.field

    raise Schnorr::InvalidSignatureError, 'Invalid signature: r is not in the field.' unless field.include?(sig.r)
    raise Schnorr::InvalidSignatureError, 'Invalid signature: s is not in the field.' unless field.include?(sig.s)
    raise Schnorr::InvalidSignatureError, 'Invalid signature: r is zero.' if sig.r.zero?
    raise Schnorr::InvalidSignatureError, 'Invalid signature: s is zero.' if sig.s.zero?

    e = create_challenge(sig.r, pubkey, message, field, group)

    r = group.new_point(sig.s) + pubkey.multiply_by_scalar(e).negate


    if r.infinity? || ECDSA::PrimeField.jacobi(r.y, group.field.prime) != 1 || r.x != sig.r
      raise Schnorr::InvalidSignatureError, 'signature verification failed.'
    end

    true
  end

  def create_challenge(x, pubkey, message, field, group)
    r = ECDSA::Format::IntegerOctetString.encode(x, group.byte_length)
    public_key = ECDSA::Format::PointOctetString.encode(pubkey, compression: true)
    field.mod(ECDSA.normalize_digest(Digest::SHA256.digest(r + public_key + message), group.bit_length))
  end

  private_class_method :create_challenge

end
