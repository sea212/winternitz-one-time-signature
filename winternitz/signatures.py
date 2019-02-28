from abc import ABCMeta, abstractmethod
from hashlib import sha256
from math import ceil, floor, log2
from os import urandom
from typing import Any, List, Optional


# Abstract definition of OTS class
class AbstractOTS(object, metaclass=ABCMeta):
    @abstractmethod
    def sign(message: bytes) -> dict:
        raise NotImplementedError("sign is essential for WOTS signatures")

    @abstractmethod
    def verify(message: bytes, signature: List[bytes]) -> bool:
        raise NotImplementedError("verify is essential for WOTS signatures")

    @abstractmethod
    def __eq__(self, obj: Any) -> bool:
        raise NotImplementedError("Equality checks are required")

    @abstractmethod
    def __ne__(self, obj: Any) -> bool:
        raise NotImplementedError("Non-equality checks are required")


# Paper describing WOTS: https://eprint.iacr.org/2011/191.pdf
# "On the Security of the Winternitz One-Time Signature Scheme"
# Note: This Class calculates with the logarithm to the base 2 of the
# Winternitz parameter. This is dues to the fact, that machine store numbers
# in binary representation, numbers like w = 5 therefore cannot be realized
# and result in w = 2**ceil(log2(w)), which would be w = 8.
# Other than that it is easier to caluclate.
class WOTS(AbstractOTS):
    def __init__(self,
                 w_log2: int,
                 hash_function: Any = sha256,  # TODO: correct Type
                 digestsize: int = 256,
                 privkey: Optional[List[bytes]] = None,
                 pubkey: Optional[List[bytes]] = None) -> None:

        if w_log2 > digestsize:
            raise ValueError("The winternitz parameter must be lower than\
                              the digestsize of the hashalgorithm")

        self.__w_log2 = w_log2

        # Calculate number of message keys, checksum keys and total keys
        self.__msg_key_count = ceil(digestsize / w_log2)
        self.__cs_key_count = ceil((floor(log2(self.__msg_key_count)) +
                                   1 + w_log2) / w_log2)
        self.__key_count = self.__msg_key_count + self.__cs_key_count

        # Hashing algorithm
        self.__hash_function = hash_function
        self.__digest_size = digestsize

        # Keys
        self.__privkey = []
        self.__pubkey = []
        hash_bytes = int(ceil(digestsize / 8))

        # generate random privkey, derive pubkey
        if privkey is None and pubkey is None:
            privkey = [pkey for pkey in urandom(hash_bytes)]
            self._derivePubKey()
        # derive pubkey
        elif privkey is not None:
            if len(privkey) != self.__key_count:
                raise ValueError("Provided private key length does not match to\
                                  provided winternitz parameter")

            self.__privkey = privkey.copy()
            self._derivePubkey()
        # set pubkey
        else:
            if len(pubkey) != self.__cs_key_count:
                raise ValueError("Provided private key length does not match to\
                                  provided winternitz parameter")

            for elem in filter(lambda t: len(t) != hash_bytes, pubkey):
                raise ValueError("Length of public key hashes does not match\
                                  with the provided digestsize")

            self.__pubkey = pubkey.copy()

    def __repr__(self) -> str:
        # TODO
        pass

    def __str__(self) -> str:
        # TODO
        pass

    def __eq__(self, obj: Any) -> bool:
        # TODO
        pass

    def __ne__(self, obj: Any) -> bool:
        # TODO
        pass

    @property
    def privkey(self) -> List[bytes]:
        # TODO: get privkey
        pass

    @property
    def pubkey(self) -> List[bytes]:
        # TODO: get privkey
        pass

    @property
    def w(self) -> int:
        return self.__w_log2
        # TODO: get Winternitz parameter
        pass

    @property
    def hashalgo(self) -> Any:  # TODO: correct Type
        # TODO: get hashalgorithm
        pass

    @property
    def digestsize(self) -> int:
        # TODO: get digestsize
        pass

    def _derivePubKey(self) -> None:
        # TODO:
        pass

    def sign(message: bytes) -> dict:
        # TODO: implement sign algorithm
        # Check if privkey none, throw exception  if it is
        pass

    def verify(message: bytes, signature: List[bytes]) -> bool:
        # TODO: implement verify algorithm
        pass


# Paper descirbing WOTS+: https://eprint.iacr.org/2017/965.pdf
# "W-OTS+ – Shorter Signatures for Hash-BasedSignature Schemes"
class WOTSPLUS(WOTS):
    def __init__(self,
                 w_log2: int,
                 hash_function: Any = sha256,  # TODO: correct Type
                 # TODO: Pseudo Random Function for Key and BM derivation
                 digestsize: int = 256,
                 privkey: Optional[List[bytes]] = None,
                 pubkey: Optional[List[bytes]] = None,
                 seed: Optional[bytes] = None):

        super().__init__(w_log2, hash_function=hash_function,
                         digestsize=digestsize, privkey=privkey,
                         pubkey=pubkey)
        # TODO
        # Only init seed if it is not None
        # Store prf
        pass

    def __repr__(self) -> str:
        # TODO
        pass

    def __str__(self) -> str:
        # TODO
        pass

    def __eq__(self, obj) -> bool:
        # TODO
        pass

    def __ne__(self, obj) -> bool:
        # TODO
        pass

    def _derivePubKey(self) -> None:
        # TODO:
        pass

    @property
    def seed(self) -> bytes:
        # TODO: get seed
        pass

    @property
    def prf(self):
        # TODO: get pseudo random function
        pass

    def sign(message: bytes) -> dict:
        # TODO: implement sign algorithm
        # Check if privkey none, throw exception  if it is
        pass

    def verify(message: bytes, signature: List[bytes]) -> bool:
        # TODO: implement verify algorithm
        pass
