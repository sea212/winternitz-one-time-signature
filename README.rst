|Build Status| |Coverage Status| |Documentation Status| |License: MIT|

Winternitz One-Time-Signature
==============================

Python implementation of Winternitz one-time-signature schemes

Description
-----------

Winternitz one-time-signature is an extension of lamport one-time-signature.
This python package can be used to execute WOTS operations, including
key generation, signature generation and signature verification.
Currently WOTS and WOTS+ are implemented.

.. _changes:
.. include:: docs/introduction.rst

Setup
-----
Requires: Python >= 3.4

| Install package: ``pip install winternitz``
| Install test tools: ``pip install winternitz[TEST]``
| Install linter (for tox tests): ``pip install winternitz[LINT]``
| Install documentation tools: ``pip install winternitz[DOCS]``
| Install everything: ``pip install winternitz[ALL]``

Test
~~~~
| Without tox (no linter checks): ``python setup.py test``
| With tox: ``python -m tox``

Generate documentation
~~~~~~~~~~~~~~~~
``python setup.py docs``


Usage
-----

TODO

Note
----

This project has been set up using PyScaffold 3.1. For details and usage
information on PyScaffold see `https://pyscaffold.org/`_.

.. _`https://pyscaffold.org/`: https://pyscaffold.org/

.. |Build Status| image:: https://www.travis-ci.com/sea212/winternitz-one-time-signature.svg?branch=master
   :target: https://www.travis-ci.com/sea212/winternitz-one-time-signature
.. |Coverage Status| image:: https://coveralls.io/repos/github/sea212/winternitz-one-time-signature/badge.svg?branch=master
   :target: https://coveralls.io/github/sea212/winternitz-one-time-signature?branch=master
.. |Documentation Status| image:: https://readthedocs.org/projects/winternitz-one-time-signature/badge/?version=latest
   :target: https://winternitz-one-time-signature.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status
.. |License: MIT| image:: https://img.shields.io/badge/License-MIT-yellow.svg
   :target: https://opensource.org/licenses/MIT
