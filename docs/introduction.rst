Introduction
------------
Lamport invented an algorithm in 1979 which allowed one to create one-time-signatures
using a cryptographically secure one-way function. It is the basis for the Winternitz
one-time-signature algorithm. Winternitz added the possibility to adjust the tradeoff
between time- and space-complexity.

Lamport one-time-signature scheme
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Lamport suggested to create two secret keys for each bit of a message which will
be signed. One for each value the bit can take. To derive the verification key,
each secret key is hashed once. Now you have a secret key and a verification key,
which consists of :math:`m` 2-tuples of values, where :math:`m` is the number
of bits of the message. The verification key is published.
The signature consists of :math:`m` values. For each bit of the message you release a secret key from
the corresponding secret keys, depending on which value the bit has. All those secret
keys form the signature for the message. The verifier hashes each of your secret keys
once and compares it to one verification key for this position, depending on the value
of the bit. The signature is valid, if and only if all derived verification keys match with
your published verification key at the correct position of the 2-tuple, which is determined by the value
of the bit. This algorithm is quite fast
(comparing it to existing PQC-algorithms), but the signature sizes are huge.

Winternitz extension
~~~~~~~~~~~~~~~~~~~~
Winternitz extended lamports algorithm by offering the possiblity to decide
how many bits will be signed together. The amount of numbers those bits can
represent is called the Winternitz parameter (:math:`w = 2^{bits}`). This method offers the huge
advantage that the user of this algorithm can choose the time and space tradeoff
(whether speed or storage capacity is more relevant). A fingerprint of the message which
will be signed is split into groups of :math:`ceil(log_2(w))` bits. Each of these groups gets one secret key.
Each verification key is derived by hashing the secret key for each group :math:`2^{w-1}` times. All verification
keys will be published and represent one unified verification key. When signing a message, the
fingerprint of the message is split into groups of :math:`ceil(log2(w))` bits. To create the signature, the
private key for each bit group is hashed :math:`bitgroup\_value` times, where :math:`bitgroup\_value` is the value
of the bitgroup. Additionally a (inverse sum) checksum is appended, which denies man-in-the-middle
attacks. The checksum is calculated from the signature, split into bit groups of :math:`ceil(log2(w))` bits, and
signed. To verify the signature, the fingerprint of the message is first split into bit groups of :math:`ceil(log2(w)`
bits each. The basic idea is to take the signature of each bit group, calculate the verification key
from it and finally compare it to the published verification key. Since the signature was hashed
:math:`bitgroup\_value` times, all you have to do to calculate the verification key from the signature
is to hash the signature :math:`2^{w-1} - bitgroup\_value - 1` times. Besides verifing the message, the verifier
must also calculate the checksum and verify it.
