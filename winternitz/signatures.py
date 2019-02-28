from hashlib import blake2b
from math import ceil, floor, log2
from typing import List, Optional


# Paper describing WOTS: https://eprint.iacr.org/2011/191.pdf
# "On the Security of the Winternitz One-Time Signature Scheme"
# Note: This Class calculates with the logarithm to the base 2 of the
# Winternitz parameter. This is dues to the fact, that machine store numbers
# in binary representation, numbers likes w = 5 therefore cannot be realized
# and result in w = 2**ceil(log2(w)), which would be w = 8.
# Other than that it is easier to caluclate.
class WOTS(object):
    def __init__(self, w_log2: int,
                 hashalgo: List[int] = blake2b,
                 digestsize=256,
                 privkey: Optional[List[bytes]] = None,
                 pubkey: Optional[List[bytes]] = None):

        if w_log2 > digestsize:
            raise ValueError("The winternitz parameter must be lower than\
                              the digestsize of the hashalgorithm")

        self.__w_log2 = w_log2

        # Calculate number of message keys, checksum keys and total keys
        self.__msg_key_count = ceil(digestsize / w_log2)
        self.__cs_key_count = ceil((floor(log2(self.__msg_key_count)) +
                                   1 + w_log2) / w_log2)
        self.__key_count = self.__msg_key_count + self.__cs_key_count

        # generate random privkey, derive pubkey
        if privkey is None and pubkey is None:
            # TODO:
            pass
        # derive pubkey
        elif privkey is not None:
            # TODO:
            pass
        # set pubkey
        else:
            self.__privkey = None

        # Cases: privkey = None and pub is set. set self.privkey to None
        # privkey set pubkey set just derive new pubkey
        # privkey not set pubkey not set just generate priv and derive pub
        pass

    def __repr__():
        # TODO
        pass

    def __str__():
        # TODO
        pass

    def __eq__():
        # TODO
        pass

    def __ne__():
        # TODO
        pass

    @property
    def privkey(self):
        # TODO: get privkey
        pass

    @property
    def pubkey(self):
        # TODO: get privkey
        pass

    @property
    def w(self):
        return self.__w_log2
        # TODO: get Winternitz parameter
        pass

    @property
    def hashalgo(self):
        # TODO: get hashalgorithm
        pass

    @property
    def digestsize(self):
        # TODO: get digestsize
        pass

    def sign(message: bytes)\
            -> dict:
        # TODO: implement sign algorithm
        # Check if privkey none, throw exception  if it is
        pass

    def verify(message: bytes, signature: List[bytes]) -> bool:
        # TODO: implement verify algorithm
        pass


# Paper descirbing WOTS+: https://eprint.iacr.org/2017/965.pdf
# "W-OTS+ – Shorter Signatures for Hash-BasedSignature Schemes"
class WOTSPLUS(WOTS):
    def __init__(self, w_log2: int,
                 hashalgo: List[int] = blake2b,
                 # TODO: Pseudo Random Function for Key and BM derivation
                 digestsize=256,
                 privkey: Optional[List[bytes]] = None,
                 pubkey: Optional[List[bytes]] = None,
                 seed: Optional[bytes] = None):
        super().__init__(w_log2, privkey, hashalgo, digestsize)
        # TODO
        # Only init seed if it is not None
        # Store prf
        pass

    def __repr__():
        # TODO
        pass

    def __str__():
        # TODO
        pass

    def __eq__():
        # TODO
        pass

    def __ne__():
        # TODO
        pass

    @property
    def seed():
        # TODO: get seed
        pass

    @property
    def prf():
        # TODO: get pseudo random function
        pass

    def sign(message: bytes)\
            -> dict:
        # TODO: implement sign algorithm
        # Check if privkey none, throw exception  if it is
        pass

    def verify(message: bytes, signature: List[bytes]) -> bool:
        # TODO: implement verify algorithm
        pass
