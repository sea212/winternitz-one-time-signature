from hashlib import sha256
from typing import List, Optional


# Paper describing WOTS: https://eprint.iacr.org/2011/191.pdf
class WOTS(object):
    def __init__(w: int, hashalgo: List[int] = sha256, digestsize=256,
                 privkey: Optional[List[bytes]] = None,
                 pubkey: Optional[List[bytes]] = None):
        # TODO

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
class WOTSPLUS(WOTS):
    def __init__(w: int, privkey: Optional[List[bytes]] = None,
                 hashalgo: List[int] = sha256, digestsize=256,
                 seed: Optional[bytes] = None):
        super().__init__(w, privkey, hashalgo, digestsize)
        # TODO
        # Only init seed if it is not None
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
