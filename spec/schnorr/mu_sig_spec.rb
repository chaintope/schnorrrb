require 'spec_helper'

RSpec.describe Schnorr::MuSig do

  describe '#compute_ell' do
    it 'should return ell' do
      pubkeys = %w(021b34e02fbfab6153513c7578de070e1c9f2654b88109fb3906bb7f63dffd957d 02bdaa2178ad0db31880dc326b1f8a6a383efd9a579962aac7008d8af738fa814d 038810e83afc4412af9070102e22305c8ae85aad98aa84263db47149f1c9790500)
      pubkeys = pubkeys.map{|k|[k].pack('H*')}
      expect(Schnorr::MuSig.compute_ell(pubkeys).unpack('H*').first).to eq('1a5695438032bc21ffdade2dbabe5b30e5d49d202e15a2f3ee87c4a45b8b5805')
    end
  end

end