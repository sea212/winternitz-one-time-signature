#!/usr/bin/env python
# -*- coding: utf-8 -*-

from math import ceil, floor, log2
from os import urandom

import pytest

import winternitz.signatures

__author__ = "Harald Heckmann"
__copyright__ = "Harald Heckmann"
__license__ = "mit"


wots = None
wots2 = None
wots_strange_w = None
wots_strange_w2 = None
wotsp = None
wotsp2 = None
wotsp_strange_w = None
wotsp_strange_w2 = None
wots_def_key_count = 0
keysize = 0


# self is of no use since pytest creates new instances for each test function
@pytest.mark.incremental
class TestWOTS(object):
    def test_init(self):
        # Init for __function__ and getter tests
        global wots, wots2, wots_strange_w, wots_strange_w2, wotsp, wotsp2,\
               wotsp_strange_w, wotsp_strange_w2, wots_def_key_count, keysize
        wots_strange_w = winternitz.signatures.WOTS(w=13)
        wots_strange_w2 = winternitz.signatures.WOTS(w=((1 << 13) + 1917))
        wots = winternitz.signatures.WOTS(w=4)
        wots2 = winternitz.signatures.WOTS(w=16)
        wotsp = winternitz.signatures.WOTSPLUS(w=4)
        wotsp2 = winternitz.signatures.WOTSPLUS(w=16)
        wotsp_strange_w = winternitz.signatures.WOTSPLUS(w=13)
        wotsp_strange_w2 = winternitz.signatures.WOTSPLUS(w=((1 << 13) + 1917))

        kswots = winternitz.signatures.WOTS()
        msgkeys = int(ceil(kswots.digestsize / log2(kswots.w)))
        cskeys = int(floor(log2(msgkeys *
                                (kswots.w - 1)) / log2(kswots.w)) + 1)
        wots_def_key_count = msgkeys + cskeys
        keysize = int(ceil(kswots.digestsize / 8))

        # Invalid w parameter
        with pytest.raises(ValueError):
            _ = winternitz.signatures.WOTS(w=1)  # noqa

        with pytest.raises(ValueError):
            _ = winternitz.signatures.WOTS(w=(1 << 513))  # noqa

        # Invalid private key size
        with pytest.raises(ValueError):
            _ = winternitz.signatures.WOTS(privkey=[b"Hi"])  # noqa

        # Invalid public key size
        with pytest.raises(ValueError):
            _ = winternitz.signatures.WOTS(pubkey=[b"Hi"])  # noqa

        # Invalid size of one element of public key
        with pytest.raises(ValueError):
            _ = winternitz.signatures.WOTS(pubkey=[urandom(1) for _ in  # noqa
                                                   range(wots_def_key_count)])

    def test_underscore_functions_and_getter(self):
        global wots, wots2, wotsp, wotsp2, wots_def_key_count, keysize
        # Object representation
        _ = str(wots2)
        _ = str(wotsp2)  # noqa: F841

        # Test string representation if public key is set
        _ = str(winternitz.signatures.WOTS(pubkey=[urandom(keysize) for
                                           _ in range(wots_def_key_count)]))

        # __repr__(self) returns a string which contains the code to be
        # executed to create an equal object. eval(...) does execute this code.
        wots_copy = eval(repr(wots))
        wotsp_copy = eval(repr(wotsp))

        # Equality checks
        assert wots == wots_copy
        assert wotsp == wotsp_copy
        assert not (wots == wots2)
        assert not (wotsp == wotsp2)

        # Not equality checks
        assert wots != wots2
        assert wotsp != wotsp2
        assert not (wots != wots_copy)
        assert not (wotsp != wotsp_copy)

        # Number to base returns [0]
        _ = wots._numberToBase(0, 16)  # noqa

        # Number conversion to another base does return more numbers than
        # private keys
        with pytest.raises(IndexError):
            wots._getSignatureBaseMessage(urandom(keysize + 1))

    def test_sign_and_verify_wots(self):
        global wots, wots_strange_w, wots_strange_w2
        WOTS = winternitz.signatures.WOTS
        message = "Hello World!".encode("utf-8")

        # Sign and verify with the same object
        sig = wots.sign(message)  # noqa: F841
        assert(wots.verify(message, sig["signature"]))

        # Sign with one object, derive the public key from checksum
        sig = wots_strange_w.sign(message)

        # Copy the object, the public key is derived from the private key
        wots_strange_w_copy = eval(repr(wots_strange_w))
        assert(wots_strange_w_copy.verify(message, sig["signature"]))

        # Create an object and specify only the public key. Verify the sig
        wots_strange_w_pub = WOTS(w=wots_strange_w.w,
                                  pubkey=wots_strange_w.pubkey)
        assert(wots_strange_w_pub.verify(message, sig["signature"]))

        # It should not be possible to sign having only a private key
        with pytest.raises(ValueError):
            _ = wots_strange_w_pub.sign(message)  # noqa

        # Verification should fail with an invalid public key
        assert(not wots2.verify(message, sig["signature"]))
        wots_same_w = WOTS(w=4)
        assert(not wots_same_w.verify(message, sig["signature"]))

        # Sign and verify with the same object using a big and strange w value
        sig = wots_strange_w2.sign(message)  # noqa: F841
        assert(wots_strange_w2.verify(message, sig["signature"]))

    def test_sign_and_verify_wots_plus(self):
        global wotsp, wotsp2, wotsp_strange_w, wotsp_strange_w2
        WOTSP = winternitz.signatures.WOTSPLUS
        message = "Hello World!".encode("utf-8")

        # Sign and verify with the same object
        sig = wotsp.sign(message)  # noqa: F841
        assert(wotsp.verify(message, sig["signature"]))

        # Sign with one object, derive the public key from checksum
        sig = wotsp_strange_w.sign(message)
        # Copy the object, the public key is derived from the private key
        wotsp_strange_w_copy = eval(repr(wotsp_strange_w))
        assert(wotsp_strange_w_copy.verify(message, sig["signature"]))

        # Create an object and specify only the public key. Verify the sig
        wotsp_strange_w_pub = WOTSP(w=wotsp_strange_w.w, pubkey=wotsp_strange_w
                                    .pubkey)
        # Should fail because we need the seed
        assert(not wotsp_strange_w_pub.verify(message, sig["signature"]))

        wotsp_strange_w_pub = WOTSP(w=wotsp_strange_w.w,
                                    seed=wotsp_strange_w.seed,
                                    pubkey=wotsp_strange_w.pubkey)
        assert(wotsp_strange_w_pub.verify(message, sig["signature"]))

        # It should not be possible to sign having only a private key
        with pytest.raises(ValueError):
            _ = wotsp_strange_w_pub.sign(message)  # noqa

        # Verification should fail with an invalid public key
        assert(not wotsp2.verify(message, sig["signature"]))
        wotsp_same_w = WOTSP(w=4, seed=wotsp_strange_w.seed)
        assert(not wotsp_same_w.verify(message, sig["signature"]))
