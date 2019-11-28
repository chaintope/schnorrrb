require 'spec_helper'

RSpec.describe Schnorr::MuSig do

  let(:vectors) { read_json('test-vectors-mu-sig.json') }

  describe '#combine_pubkey' do
    it 'should return combined public key' do
      vectors.each do |vec|
        result = Schnorr::MuSig.pubkey_combine(vec['pubKeys'].map{|p|[p].pack('H*')})
        expect(result.unpack('H*').first).to eq(vec['pubKeyCombined'])
      end
    end
  end

  describe '#session_initialize' do
    it 'should return session.' do
      vectors.each do |vec|
        combined_pubkey, private_keys, ell, message, sessions = load_data(vec)
        private_keys.each_with_index do |key, index|
          num_singers = vec['pubKeys'].length
          session_id = [vec['sessionIds'][index]].pack('H*')
          session = Schnorr::MuSig.session_initialize(session_id, key, message, combined_pubkey, ell, index, num_singers)
          expect(session.commitment.unpack('H*').first).to eq(vec['commitments'][index])
          expect(session.secret_key.to_hex).to eq(vec['secretKeys'][index])
          expect(session.secret_nonce.to_hex).to eq(vec['secretNonces'][index])
        end
      end
    end
  end

  describe '#session_nonce_combine' do
    it 'should return combined nonce.' do
      vectors.each do |vec|
        combined_pubkey, private_keys, ell, message, sessions = load_data(vec)
        others = sessions.map(&:nonce)
        others.delete(sessions[0].nonce)
        result = sessions[0].combine_nonce(others)
        expect(result.unpack('H*').first).to eq(vec['nonceCombined'])
      end
    end
  end

  describe '#partial_sign' do
    it 'should be signed.' do
      vectors.each do |vec|
        combined_pubkey, private_keys, ell, message, sessions = load_data(vec)
        others = sessions.map(&:nonce)
        others.delete(sessions[0].nonce)
        combined_nonce = sessions[0].combine_nonce(others)
        sessions.each_with_index do |session, index|
          session.nonce_negate = sessions[0].nonce_negate
          expect(session.partial_sign(message, combined_nonce, combined_pubkey).to_hex).to eq(vec['partialSigs'][index])
        end
      end
    end
  end

  describe '#partial_sig_combine' do
    it 'should return combined signature.' do
      vectors.each do |vec|
        combined_pubkey, private_keys, ell, message, sessions = load_data(vec)
        others = sessions.map(&:nonce)
        others.delete(sessions[0].nonce)
        combined_nonce = sessions[0].combine_nonce(others)
        signatures = sessions.map do |session|
          session.nonce_negate = sessions[0].nonce_negate
          session.partial_sign(message, combined_nonce, combined_pubkey)
        end
        signature = Schnorr::MuSig.partial_sig_combine(combined_nonce, signatures)
        expect(signature.encode.unpack('H*').first).to eq(vec['signature'])
        expect(Schnorr.valid_sig?(message, combined_pubkey, signature.encode)).to be true
      end
    end
  end

  def load_data(vec)
    public_keys = vec['pubKeys'].map{|p|[p].pack('H*')}
    combined_pubkey = [vec['pubKeyCombined']].pack('H*')
    private_keys = vec['privKeys'].map{|k|k.to_i(16)}
    ell = Schnorr::MuSig.compute_ell(public_keys)
    message = [vec['message']].pack('H*')
    commitments = vec['commitments'].map{|c|[c].pack('H*')}
    sessions = private_keys.map.with_index do |key, index|
      num_singers = vec['pubKeys'].length
      session_id = [vec['sessionIds'][index]].pack('H*')
      session = Schnorr::MuSig.session_initialize(session_id, key, message, combined_pubkey, ell, index, num_singers)
      commitments.each do |c|
        session.commitments << c unless c == session.commitment
      end
      session
    end
    [combined_pubkey, private_keys, ell, message, sessions]
  end
end