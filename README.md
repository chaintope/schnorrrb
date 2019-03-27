# Schnorrrb [![Build Status](https://travis-ci.org/chaintope/schnorrrb.svg?branch=master)](https://travis-ci.org/chaintope/schnorrrb) [![Gem Version](https://badge.fury.io/rb/schnorr.svg)](https://badge.fury.io/rb/schnorr) [![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE) 

This is a Ruby implementation of the Schnorr signature scheme over the elliptic curve. 
This implementation relies on the [ecdsa gem](https://github.com/DavidEGrayson/ruby_ecdsa) for operate elliptic curves.

The code is based upon the initial proposal of Pieter Wuille's [bip-schnorr](https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki).

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

### Change elliptic curve

This library use `secp256k1` curve as default. If you use another curve, you need to specify curve as following:

```ruby
Schnorr.sign(message, private_key, group: ECDSA::Group::xxx)

Schnorr.valid_sig?(message, public_key, signature, group: ECDSA::Group::xxx) 
```

Note: But this library has only been tested with `secp256k1`. So another curve are not tested.

## TODO

The following is unimplemented now.

* batch verification.
* MuSig