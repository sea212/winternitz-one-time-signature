#!/usr/bin/env python
# -*- coding: utf-8 -*-

# import pytest

from winternitz.signatures import WOTS, WOTSPLUS

# rom unittest import assertTrue, assertFalse

__author__ = "Harald Heckmann"
__copyright__ = "Harald Heckmann"
__license__ = "mit"


def test_underscore_functions_and_getter():
    # TODO: write some serious tests
    # Init
    wots = WOTS(4)
    wots2 = WOTS(16)
    wotsp = WOTSPLUS(4)
    wotsp2 = WOTSPLUS(16)

    # Object representation
    _ = wots.__repr__()
    _ = wots2.__str__()
    _ = wotsp.__repr__()
    _ = wotsp2.__str__()  # noqa: F841

    # Equality checks
    assert wots == wots
    assert wotsp == wotsp
    assert not (wots == wots2)
    assert not (wotsp == wotsp2)

    # Not equality checks
    assert wots != wots2
    assert wotsp != wotsp2
    assert not (wots != wots)
    assert not (wotsp != wotsp)
