from abc import ABCMeta, abstractmethod
from hashlib import sha256
from math import ceil, floor, log2
from os import urandom
from typing import Any, List, Optional

__author__ = "Harald Heckmann"
__copyright__ = "Harald Heckmann"
__license__ = "mit"

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
                 hash_class: Any = sha256,  # TODO: correct Type
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
        self.__hash_class = hash_class
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
        repr = "winternitz.signatures.WOTS(w_log2={}, hash_class={}, " + \
               "digestsize={}, "
        repr = repr.format(self.w, str(self.hashclass.__module__) +
                           "." + str(self.hashclass.__qualname__),
                           self.digestsize)

        if self.privkey is None:
            return repr + "pubkey=" + str(self.pubkey) + ")"
        else:
            return repr + "privkey=" + str(self.privkey) + ")"

    def __str__(self) -> str:
        fstr = "Package: winternitz\nLibrary: signatures\nClass: WOTS\n" + \
               "Winternitz Parameter (log2): {}\nHash algorithm: {}\n" + \
               "Digest size: {}\n"
        fstr += "Private key:\n" if self.privkey is not None else \
                "Public key:\n"

        for idx, key in enumerate(self.privkey if self.privkey is not None
                                  else self.pubkey):
            fstr += "\t[{}] {}\n".format(idx, key)

        return fstr.format(self.w, self.hashclass.__qualname__,
                           self.digestsize)

    def __eq__(self, obj: Any) -> bool:
        return isinstance(obj, self.__class__) and self.w == obj.w and \
            self.hashclass == obj.hashclass and self.digestsize == \
            obj.digestsize and self.privkey == obj.privkey and \
            self.pubkey == obj.pubkey

    def __ne__(self, obj: Any) -> bool:
        return not self.__eq__(obj)

    @property
    def privkey(self) -> List[bytes]:
        return self.__privkey.copy()

    @property
    def pubkey(self) -> List[bytes]:
        return self.__pubkey.copy()

    @property
    def w(self) -> int:
        return self.__w_log2

    @property
    def hashclass(self) -> Any:  # TODO: correct Type
        return self.__hash_class

    @property
    def digestsize(self) -> int:
        return self.__digest_size

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
                 hash_class: Any = sha256,  # TODO: correct Type
                 # TODO: Pseudo Random Function for Key and BM derivation
                 digestsize: int = 256,
                 privkey: Optional[List[bytes]] = None,
                 pubkey: Optional[List[bytes]] = None,
                 seed: Optional[bytes] = None):

        super().__init__(w_log2, hash_class=hash_class,
                         digestsize=digestsize, privkey=privkey,
                         pubkey=pubkey)

        if seed is None:
            seed = urandom(int(ceil(digestsize/8)))

        self.__seed = seed
        # TODO: store prf
        pass

    def __repr__(self) -> str:
        # TODO: add prf
        return super().__repr__().replace("WOTS", "WOTSPLUS")[:-1] + \
               ", seed=" + str(self.seed) + ")"

    def __str__(self) -> str:
        # TODO: add prf
        sstr = super().__str__().replace("WOTS", "WOTSPLUS")
        strsplit = sstr.split("Public key:" if self.privkey is None else
                              "Private key:")
        result = strsplit[0] + "Seed: " + str(self.__seed) + \
            ("\nPublic key: " if self.privkey is None else
             "\nPrivate key: ") + strsplit[1]

        return result

    def __eq__(self, obj) -> bool:
        # TODO: add prf
        return super().__eq__(obj) and isinstance(obj, self.__class__) and \
            self.seed == obj.seed

    def __ne__(self, obj) -> bool:
        return not self.__eq__(obj)

    def _derivePubKey(self) -> None:
        # TODO:
        pass

    @property
    def seed(self) -> bytes:
        return self.__seed

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
