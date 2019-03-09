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

Previous history
~~~~~~~~~~~~~~~~
Lamport suggested to create two secret keys for each bit of a message which will
be signed. One for each value the bit can take. To derive the verification key,
each secret key is hashed once. Now you have a secret key and a verification key,
which consists of m 2-tuples of values, where m is the number of bits of the message.
The verification key is published.
The signature consists of m values. For each bit of the message you release a secret key from
the corresponding secret keys, depending on which value the bit has. All those secret
keys form the signature for the message. The verifier hashes each of your secret keys
once and compares it to one verification key for this position, depending on the value
of the bit. The signature is valid, if and only if all derived verification keys match with
your published verification key at the correct position of the 2-tuple, which is determined by the value
of the bit. This algorithm is quite fast
(comparing it to existing PQC-algorithms), but the signature sizes are huge.

Winternitz extension
~~~~~~~~~~~~~~~~~~~
Winternitz extended lamports algorithm by offering the possiblity to decide
how many bits will be signed together. The amount of numbers those bits can
represent is called the Winternitz parameter (w = 2^(bits)). This method offers the huge
advantage that the user of this algorithm can choose the time and space tradeoff
(whether speed or storage capacity is more relevant). A fingerprint of the message which
will be signed is split into groups of log2(w) bits. Each of these groups gets one secret key.
Each verification key is derived by hashing the secret key for each group 2^(w-1) times. All verification
keys will be published and represent one unified verification key. When signing a message, the
fingerprint of the message is split into groups of log2(w) bits. To create the signature, the
private key for each bit group is hashed bitgroup_value times, where bitgroup_value is the value
of the bitgroup. Additionally a (inverse sum) checksum is appended, which denies man-in-the-middle
attacks. The checksum is calculated from the signature, split into bit groups of log2(w) bits, and
signed. To verify the signature, the fingerprint of the message is split into bit groups of log2(w)
bits each. The basic idea is to take the signature of each bit group, calculate the verification key
from it and finally compare it to the published verification key. Since the signature was hashed
bitgroup_value times, all you have to do to calculate the verification key from the signature
is to hash the signature 2^(w-1) - bitgroup_value times. Besides verifing the message, the verifier
must also calculate the checksum and verify it.

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
