require 'ecdsa'
require 'securerandom'
require_relative 'schnorr/signature'
require_relative 'schnorr/mu_sig'

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

  # Batch verification
  # @param messages (Array[String]) The array of message with binary format.
  # @param public_keys (Array[String]) The array of public key with binary format.
  # @param signatures (Array[String]) The array of signatures with binary format.
  # @param group (ECDSA::Group) The curve that is being used.
  # @return (Boolean) whether signature is valid.
  def valid_sigs?(messages, public_keys, signatures, group: ECDSA::Group::Secp256k1)
    raise ArgumentError, 'all parameters must be an array with the same length.' if messages.size != public_keys.size || public_keys.size != signatures.size
    field = group.field
    pubkeys = public_keys.map{|p| ECDSA::Format::PointOctetString.decode(p, group)}
    sigs = signatures.map do|signature|
      sig = Schnorr::Signature.decode(signature)
      raise Schnorr::InvalidSignatureError, 'Invalid signature: r is not in the field.' unless field.include?(sig.r)
      raise Schnorr::InvalidSignatureError, 'Invalid signature: s is not in the field.' unless field.include?(sig.s)
      raise Schnorr::InvalidSignatureError, 'Invalid signature: r is zero.' if sig.r.zero?
      raise Schnorr::InvalidSignatureError, 'Invalid signature: s is zero.' if sig.s.zero?
      sig
    end
    left = 0
    right = nil
    pubkeys.each_with_index do |pubkey, i|
      r = sigs[i].r
      s = sigs[i].s
      e = create_challenge(r, pubkey, messages[i], field, group)
      c = field.mod(r.pow(3) + 7)
      y = c.pow((field.prime + 1)/4, field.prime)
      raise Schnorr::InvalidSignatureError, 'c is not equal to y^2.' unless c == y.pow(2, field.prime)
      r_point = ECDSA::Point.new(group, r, y)
      if i == 0
        left = s
        right = r_point + pubkey.multiply_by_scalar(e)
      else
        a = 1 + SecureRandom.random_number(group.order - 1)
        left += (a * s)
        right += (r_point.multiply_by_scalar(a) + pubkey.multiply_by_scalar(a * e))
      end
    end
    group.new_point(left) == right
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

  class ::Integer

    def to_hex
      hex = to_s(16)
      hex.rjust((hex.length / 2.0).ceil * 2, '0')
    end

    def method_missing(method, *args)
      return mod_pow(args[0], args[1]) if method == :pow && args.length < 3
      super
    end

    # alternative implementation of Integer#pow for ruby 2.4 and earlier.
    def mod_pow(x, y)
      return self ** x unless y
      b = self
      result = 1
      while x > 0
        result = (result * b) % y if (x & 1) == 1
        x >>= 1
        b = (b * b) % y
      end
      result
    end

  end

end
