#!/usr/bin/env python
# -*- coding: utf-8 -*-

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


# self is of no use since pytest creates new instances for each test function
@pytest.mark.incremental
class TestWOTS(object):
    def test_init(self):
        # Init for __function__ and getter tests
        global wots, wots2, wots_strange_w, wots_strange_w2, wotsp, wotsp2
        wots_strange_w = winternitz.signatures.WOTS(w=13)
        wots_strange_w2 = winternitz.signatures.WOTS(w=((1 << 17) + 1917))
        wots = winternitz.signatures.WOTS(w=4)
        wots2 = winternitz.signatures.WOTS(w=16)
        wotsp = winternitz.signatures.WOTSPLUS(w=4)
        wotsp2 = winternitz.signatures.WOTSPLUS(w=16)

    def test_underscore_functions_and_getter(self):
        global wots, wots2, wotsp, wotsp2
        # Object representation
        _ = str(wots2)
        _ = str(wotsp2)  # noqa: F841

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

    def test_sign_and_verify(self):
        # Do it better!
        global wots, wots_strange_w
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
        wots_strange_w_pub = winternitz.signatures\
                                       .WOTS(w=wots_strange_w.w,
                                             pubkey=wots_strange_w.pubkey)
        assert(wots_strange_w_pub.verify(message, sig["signature"]))
