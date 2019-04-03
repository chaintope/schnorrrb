# Schnorrrb [![Build Status](https://travis-ci.org/chaintope/schnorrrb.svg?branch=master)](https://travis-ci.org/chaintope/schnorrrb) [![Gem Version](https://badge.fury.io/rb/schnorr.svg)](https://badge.fury.io/rb/schnorr) [![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE) 

This is a Ruby implementation of the Schnorr signature scheme over the elliptic curve. 
This implementation relies on the [ecdsa gem](https://github.com/DavidEGrayson/ruby_ecdsa) for operate elliptic curves.

The code is based upon the initial proposal of Pieter Wuille's [bip-schnorr](https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki).

## Requirements

* Ruby 2.5+

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'schnorr'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install schnorr

## Usage

### Singing

```ruby
require 'schnorr'

private_key = 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF

message = ['5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C'].pack('H*')

# create signature
signature = Schnorr.sign(message, private_key)

# signature r value
signature.r 

# signature s value
signature.s 

# convert signature to binary

signature.encode

```

### Verification

```ruby
require 'schnorr'

public_key = ['03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B'].pack('H*')

signature = [`00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE00880371D01766935B92D2AB4CD5C8A2A5837EC57FED7660773A05F0DE142380`].pack('H*')

message = ['5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C'].pack('H*')

# verify signature.(result is true or false)
result = Schnorr.valid_sig?(message, public_key, signature) 

# signature convert to Signature object
sig = Schnorr::Signature.decode(signature) 
```

### Batch verification

```ruby
require 'schnorr'

pubkeys = ['03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B'].pack('H*')
pubkeys << ['02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659'].pack('H*')
...

messages = ['5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C'].pack('H*')
messages << ['243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89'].pack('H*')
...

signatures = [`00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE00880371D01766935B92D2AB4CD5C8A2A5837EC57FED7660773A05F0DE142380`].pack('H*')
signatures << [`787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF68FCE5677CE7A623CB20011225797CE7A8DE1DC6CCD4F754A47DA6C600E59543C`].pack('H*')
...

# batch verify signature.(result is true or false)
result = Schnorr.valid_sig?(messages, pubkeys, signatures) 
```

### Change elliptic curve

This library use `secp256k1` curve as default. If you use another curve, you need to specify curve as following:

```ruby
Schnorr.sign(message, private_key, group: ECDSA::Group::xxx)

Schnorr.valid_sig?(message, public_key, signature, group: ECDSA::Group::xxx) 
```

Note: But this library has only been tested with `secp256k1`. So another curve are not tested.

## TODO

The following is unimplemented now.

* MuSig