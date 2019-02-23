#!/usr/bin/env python
# -*- coding: utf-8 -*-

# import pytest

from winternitz.signatures import WOTS, WOTSPLUS

__author__ = "Harald Heckmann"
__copyright__ = "Harald Heckmann"
__license__ = "mit"


def test_init():
    # write some serious tests
    _ = WOTS(16)
    _ = WOTSPLUS(16)
