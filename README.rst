|Build Status| |Coverage Status| |License: MIT| |Documentation Status|

Winternitz One-Time-Signatures
==============================

Python implementation of Winternitz one-time-signatures schemes

Description
-----------

Winternitz one-time-signatures are an extension of lamport one-time-signatures.
This python package can be used to execute WOTS operations, including
key generation, signature generation and signature verification.
Currently WOTS and WOTS+ are implemented.

Previous history
~~~~~~~~~~~~~~~~
Lamport suggested to create a secret key for each bit of a message which will
be signed. Each public key is derived from the secret key by hashing it once.
The digital signature consists of the private key. This algorithm is quite fast
(regarding existing PQC-algorithms), but the signatures sizes are huge.

Winternitz extension
~~~~~~~~~~~~~~~~~~~
Winternitz extended lamports algorithm by offering the possiblity to decide
how many bits will be signed together. The amount of numbers those bits can
represent is called the Winternitz parameter (w = 2^(bits)). This method offers the huge
advantage that the user of this algorithm can choose the time and space tradeoff
(whether speed or storage capacity is more relevant). A fingerprint of the message which
will be signed is split into groups of log2(w) bits. Each of these groups gets one secret key.
Each public key is derived by hashing the secret key for each group 2^(w-1) times. All public
keys will be published and represent one unified public key. When signing a message, the
fingerprint of the message is split into groups of log2(w) bits. To create the signature, the
private key for each bit group is hashed bitgroup_value times, where bitgroup_value is the value
of the bitgroup. Additionally a (inverse sum) checksum is appended, which denies man-in-the-middle
attacks. The checksum is calculated from the signature, split into bit groups of log2(w) bits, and
signed. To verify the signature, the fingerprint of the message is split into bit groups of log2(w)
bits each. The basic idea is to take the signature of each bit group, calculate the public key
from it and finally compare it to the published public key. Since the signature was hashed
bitgroup_value times, all you have to do to calculate the public key from the signature
is to hash the signature 2^(w-1) - bitgroup_value times. Besides verifing the message, the verifier
must also calculate the checksum and verify it.

Setup
-----
Requires: Python >= 3.4

| Install package: ``python setup.py install``
| Install test tools: ``pip install winternitz[testing]``
| Install linter (for tox tests): ``pip install winternitz[lint]``
| Install documentation tools: ``pip install winternitz[docs]``
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
.. |License: MIT| image:: https://img.shields.io/badge/License-MIT-yellow.svg
   :target: https://opensource.org/licenses/MIT
.. |Documentation Status| image:: https://readthedocs.org/projects/winternitz-one-time-signatures/badge/?version=latest
   :target: https://winternitz-one-time-signatures.readthedocs.io/en/latest/?badge=latest
