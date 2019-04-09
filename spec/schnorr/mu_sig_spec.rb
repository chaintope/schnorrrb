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
        public_keys = vec['pubKeys'].map{|p|[p].pack('H*')}
        combined_pubkey = [vec['pubKeyCombined']].pack('H*')
        private_keys = vec['privKeys'].map{|k|k.to_i(16)}
        ell = Schnorr::MuSig.compute_ell(public_keys)
        message = [vec['message']].pack('H*')
        private_keys.each_with_index do |key, index|
          session_id = [vec['sessionIds'][index]].pack('H*')
          session = Schnorr::MuSig.session_initialize(session_id, key, message, combined_pubkey, ell, index)
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
        public_keys = vec['pubKeys'].map{|p|[p].pack('H*')}
        combined_pubkey = [vec['pubKeyCombined']].pack('H*')
        private_keys = vec['privKeys'].map{|k|k.to_i(16)}
        ell = Schnorr::MuSig.compute_ell(public_keys)
        message = [vec['message']].pack('H*')

        sessions = private_keys.map.with_index do |key, index|
          session_id = [vec['sessionIds'][index]].pack('H*')
          Schnorr::MuSig.session_initialize(session_id, key, message, combined_pubkey, ell, index)
        end
        others = sessions.map(&:nonce)
        others.delete(sessions[0].nonce)
        result = sessions[0].nonce_combine(others)
        expect(result.unpack('H*').first).to eq(vec['nonceCombined'])
      end
    end
  end

end