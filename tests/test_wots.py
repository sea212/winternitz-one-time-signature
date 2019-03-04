#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pytest

import winternitz.signatures

__author__ = "Harald Heckmann"
__copyright__ = "Harald Heckmann"
__license__ = "mit"


wots = None
wots2 = None
wotsp = None
wotsp2 = None


# self is of no use since pytest creates new instances for each test function
@pytest.mark.incremental
class TestWOTS(object):
    def test_init(self):
        # Init for __function__ and getter tests
        global wots, wots2, wotsp, wotsp2
        wots = winternitz.signatures.WOTS(4)
        wots2 = winternitz.signatures.WOTS(16)
        wotsp = winternitz.signatures.WOTSPLUS(4)
        wotsp2 = winternitz.signatures.WOTSPLUS(16)

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
        global wots
        sig = wots.sign("Hello World!".encode("utf-8"))  # noqa: F841
