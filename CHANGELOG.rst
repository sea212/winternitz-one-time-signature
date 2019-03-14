=========
Changelog
=========

Version 1.0
===========

- First fully tested and documented release of the winternitz package
- Contains AbstractOTS base class for OTS implementations in this package
- Contains fully configurable Winternitz One-Time-Signature scheme
- Contains fully configurable Winternitz One-Time-Signature+ scheme

Version 1.0.1
=============

- Fixed bug that sign(...) returned the pubkeys (list) inside a list
- Further examples added

Version 1.0.2
=============

- sign(...) does now additionally return the OTS algorithm used
- sign(...) does not return the fingerprint of the message anymore
- Implemented getPubkeyFromSignature(...)
- Tested and documented getPubkeyFromSignature(...)
