require 'spec_helper'
require 'csv'

RSpec.describe Schnorr do

  it "has a version number" do
    expect(Schnorr::VERSION).not_to be nil
  end

  # https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr/test-vectors.csv
  describe 'Test Vector' do
    it 'should be passed.' do
      vectors = CSV.read(File.join(File.dirname(__FILE__), 'fixtures', 'test-vectors.csv'), headers: true)
      vectors.each do |v|
        priv_key = v['secret key'] ? v['secret key'].to_i(16) : nil
        pubkey = v['public key']
        message = [v['message']].pack('H*')
        expected_sig = v['signature']
        result = v['verification result'] == 'TRUE'
        if priv_key
          signature = Schnorr.sign(message, priv_key)
          expect(signature.encode.unpack('H*').first.upcase).to eq(expected_sig)
        end
      end
    end

  end

end
