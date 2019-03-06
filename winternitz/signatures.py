from abc import ABCMeta, abstractmethod
from hashlib import sha256
from hmac import new as new_hmac
from math import ceil, floor, log2
from os import urandom
from typing import Any, List, Optional

__author__ = "Harald Heckmann"
__copyright__ = "Harald Heckmann"
__license__ = "mit"


def openssl_sha256(message: bytes) -> bytes:
    return sha256(message).digest()


def hmac_openssl_sha256(key: bytes, message: bytes) -> bytes:
    return new_hmac(key=key, msg=message, digestmod=sha256).digest()


# Abstract definition of OTS class
class AbstractOTS(object, metaclass=ABCMeta):
    """ OTS base class

    Every class implementing OTS schemes in this package should implement the
    functions defined in this base class
    """
    @abstractmethod
    def sign(message: bytes) -> dict:
        """ Sign a message

        This function will create a valid signature for a message on success

        Args:
            message: Encoded message to sign

        Returns:
            Signature
        """
        raise NotImplementedError("sign is essential for WOTS signatures")

    @abstractmethod
    def verify(message: bytes, signature: List[bytes]) -> bool:
        """ Verify a message

        Verify whether a signature is valid for a message

        Args:
            message:    Encoded message to verify
            signature:  Signature that will be used to verify the message

        Returns:
            Whether the verification succeded
        """
        raise NotImplementedError("verify is essential for WOTS signatures")

    @abstractmethod
    def __eq__(self, obj: Any) -> bool:
        """ Object equality check

        Compare the relevant data within the called object and obj

        Args:
            obj: The object to compare the called object with

        Returns:
            Whether the the calling object and obj are equal
        """
        raise NotImplementedError("Equality checks are required")

    @abstractmethod
    def __ne__(self, obj: Any) -> bool:
        """ Object non-equality check

        Compare the relevant data within the called object and obj

        Args:
            obj: The object to compare the called object with

        Returns:
            Whether the the calling object and obj are not equal
        """
        raise NotImplementedError("Non-equality checks are required")


# Paper describing WOTS: https://eprint.iacr.org/2011/191.pdf
# "On the Security of the Winternitz One-Time Signature Scheme"
class WOTS(AbstractOTS):
    """ Winternitz One-Time-Signature

    Fully configurable class in regards to Winternitz paramter, hash function,
    private key and public key
    """
    def __init__(self,
                 w: int,
                 hash_function: Any = openssl_sha256,  # TODO: correct Type
                 digestsize: int = 256,
                 privkey: Optional[List[bytes]] = None,
                 pubkey: Optional[List[bytes]] = None) -> None:
        """ Initialize WOTS object

        Define under which circumstances a message should be signed or verified

        Args:
            w:              The Winternitz parameter. A higher value reduces
                            the space complexity, but increases the time
                            complexity. It must be greater than 1 but less than
                            :math: 2^{digestsize}. To get the best space to
                            time complexity ratio, choose a value that is a
                            power of two.
            hash_function:  The hashfunction which will be used to derive
                            signatures and public keys. Specify a function
                            which takes bytes as an argument and returns
                            bytes that represent the hash.
            digestsize:     The number of bits that will be emitted by the
                            specified hash function.
            privkey:        The private key to be used for signing operations.
                            Leave None if it should be generated

        Returns:
            Whether the the calling object and obj are not equal
        """

        self.__w = w

        if not (2 <= w <= (1 << digestsize)):
            raise ValueError("Rule broken: 2 <= w <= 2^digestsize")

        # Calculate number of message keys, checksum keys and total keys
        self.__msg_key_count = int(ceil(digestsize / log2(w)))
        self.__cs_key_count = int(floor(log2(self.__msg_key_count *
                                        (w - 1)) / log2(w)) + 1)
        self.__key_count = self.__msg_key_count + self.__cs_key_count

        # Hashing algorithm
        self.__hashfunction = hash_function
        self.__digestsize = digestsize

        # Keys
        self.__privkey = None
        self.__pubkey = None
        hash_bytes = int(ceil(digestsize / 8))

        # set privkey
        if privkey is not None:
            if len(privkey) != self.__key_count:
                raise ValueError("Provided private key length does not match to\
                                  provided winternitz parameter")

            self.__privkey = privkey.copy()
        # set pubkey, but only is privkey is not set
        elif pubkey is not None:
            if len(pubkey) != self.__cs_key_count:
                raise ValueError("Provided public key length does not match to\
                                  provided winternitz parameter")

            for elem in filter(lambda t: len(t) != hash_bytes, pubkey):
                raise ValueError("Length of public key hashes does not match\
                                  with the provided digestsize")

            self.__pubkey = pubkey.copy()

    def __repr__(self) -> str:
        repr = "winternitz.signatures.WOTS(w={}, hash_function={}, " + \
               "digestsize={}, "
        repr = repr.format(self.__w, str(self.__hashfunction.__module__) +
                           "." + str(self.__hashfunction.__qualname__),
                           self.__digestsize)

        if self.__privkey is None and self.__pubkey is not None:
            return repr + "pubkey=" + str(self.__pubkey) + ")"

        return repr + "privkey=" + str(self.privkey) + ")"

    def __str__(self) -> str:
        fstr = "Package: winternitz\nLibrary: signatures\nClass: WOTS\n" + \
               "Winternitz Parameter: {}\nHash algorithm: {}\n" + \
               "Digest size: {}\n"

        privkey = self.privkey  # only copy once if at all

        if privkey is not None:
            fstr += "Private key:\n"

            for idx, key in enumerate(self.privkey):
                fstr += "\t[{}] {}\n".format(idx,
                                             hex(int.from_bytes(key, "big")))

        fstr += "Public key:\n"

        for idx, key in enumerate(self.pubkey):
            fstr += "\t[{}] {}\n".format(idx,
                                         hex(int.from_bytes(key, "big")))

        return fstr.format(self.__w, self.hashfunction.__qualname__,
                           self.digestsize)

    def __eq__(self, obj: Any) -> bool:
        return isinstance(obj, self.__class__) and self.__w == obj.w and \
            self.__hashfunction == obj.hashfunction and self.__digestsize == \
            obj.digestsize and self.privkey == obj.privkey and \
            self.pubkey == obj.pubkey

    def __ne__(self, obj: Any) -> bool:
        return not self.__eq__(obj)

    @property
    def privkey(self) -> List[bytes]:
        if self.__privkey is None:
            if self.__pubkey is None:
                self.__privkey = [urandom(int(ceil(self.__digestsize / 8)))
                                  for pk in range(self.__key_count)]
            else:
                return []

        return self.__privkey.copy()

    @property
    def pubkey(self) -> List[bytes]:
        if self.__pubkey is None:
            self.__pubkey = [self._chain(privkey, 0, self.__w - 1)
                             for privkey in self.privkey]

        return self.__pubkey.copy()

    @property
    def w(self) -> int:
        return self.__w

    @property
    def hashfunction(self) -> Any:  # TODO: correct Type
        return self.__hashfunction

    @property
    def digestsize(self) -> int:
        return self.__digestsize

    def _chain(self, value: bytes, startidx: int, endidx: int) -> bytes:
        for i in range(startidx, endidx):
            value = self.__hashfunction(value)

        return value

    def _checksum(self, values: List[int]) -> int:
        # Inverse sum checksum
        result = 0

        for value in values:
            result += self.__w - 1 - value

        return result

    def _numberToBase(self, num: int, base: int) -> List[int]:
        if num == 0:
            return [0]

        digits = []

        while num:
            digits.append(int(num % base))
            num //= base

        return digits[::-1]

    def _getSignatureBaseMessage(self, msghash: bytes) -> List[bytes]:
        msgnum = int.from_bytes(msghash, "big")
        msg_to_sign = self._numberToBase(msgnum, self.__w)

        if (len(msg_to_sign) > self.__msg_key_count):
            err = "The fingerprint of the message could not be split into the"\
                  + " expected amount of bitgroups. This is most likely "\
                  + "because the digestsize specified does not match to the " \
                  + " real digestsize of the specified hashfunction Excepted:"\
                  + " {} bitgroups\nGot: {} bitgroups"
            raise IndexError(err.format(self.__msg_key_count,
                                        len(msg_to_sign)))

        msg_to_sign += [0] * (self.__msg_key_count - len(msg_to_sign))  # pad
        checksum = self._numberToBase(self._checksum(msg_to_sign), self.__w)
        checksum += [0] * (self.__cs_key_count - len(checksum))  # pad
        return msg_to_sign + checksum

    def sign(self, message: bytes) -> dict:
        privkey = self.privkey

        if privkey is None:
            raise ValueError("Unable to sign the message, only a public key "
                             + "was specified")

        msghash = self.__hashfunction(message)
        msg_to_sign = self._getSignatureBaseMessage(msghash)
        signature = [self._chain(privkey[idx], 0, val)
                     for idx, val in enumerate(msg_to_sign)]

        # If the pubkey is not set yet, derive it from the signature
        if (self.__pubkey is None):
            self.__pubkey = [self._chain(signature[idx], val,
                             self.__w - 1)
                             for idx, val in enumerate(msg_to_sign)]

        return {
            "fingerprint": msghash,
            "signature": signature,
            "pubkey": self.__pubkey
        }

    def verify(self, message: bytes, signature: List[bytes]) -> bool:
        if len(signature) != self.__key_count:
            return False

        msghash = self.__hashfunction(message)
        msg_to_verify = self._getSignatureBaseMessage(msghash)
        pubkey = [self._chain(signature[idx], val, self.__w - 1)
                  for idx, val in enumerate(msg_to_verify)]
        return True if pubkey == self.pubkey else False


# Paper descirbing WOTS+: https://eprint.iacr.org/2017/965.pdf
# "W-OTS+ – Shorter Signatures for Hash-Based Signature Schemes"
class WOTSPLUS(WOTS):
    def __init__(self,
                 w: int,
                 hash_function: Any = openssl_sha256,  # TODO: correct Type
                 prf: Any = hmac_openssl_sha256,  # TODO: correct Type
                 digestsize: int = 256,
                 seed: Optional[bytes] = None,
                 privkey: Optional[List[bytes]] = None,
                 pubkey: Optional[List[bytes]] = None):

        super().__init__(w, hash_function=hash_function,
                         digestsize=digestsize, privkey=privkey,
                         pubkey=pubkey)

        self.__seed = seed
        self.__prf = prf

    def __repr__(self) -> str:
        return super().__repr__().replace("WOTS", "WOTSPLUS")[:-1] + \
               ", seed={}, prf={})".format(str(self.seed),
                                           str(self.prf.__module__) + "." +
                                           str(self.prf.__qualname__))

    def __str__(self) -> str:
        sstr = super().__str__().replace("WOTS", "WOTSPLUS")
        strsplit = sstr.split("Public key:" if self.privkey is None else
                              "Private key:")
        result = strsplit[0] \
            + "Pseudo random function: " + str(self.prf.__qualname__) \
            + "\nSeed: " + hex(int.from_bytes(self.seed, "big")) \
            + ("\nPublic key: " if self.privkey is None else
               "\nPrivate key: ") + strsplit[1]

        return result

    def __eq__(self, obj) -> bool:
        return super().__eq__(obj) and isinstance(obj, self.__class__) and \
            self.seed == obj.seed and self.prf == obj.prf

    def __ne__(self, obj) -> bool:
        return not self.__eq__(obj)

    @property
    def seed(self) -> bytes:
        if self.__seed is None:
            self.__seed = urandom(int(ceil(self.digestsize / 8)))

        return self.__seed

    @property
    def prf(self):
        return self.__prf

    """
    # https://tools.ietf.org/html/rfc8391#section-3.1.2
    def _chain(self) -> None:
        # TODO:
        pass
    """
