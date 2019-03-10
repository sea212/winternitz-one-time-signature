Usage
=====

The package *winternitz* contains a module called *signatures*.
Within this package you can find the classes WOTS and WOTSPLUS.
Those classes can be used out of the box to sign or verify
messages

WOTS
----
.. code-block:: python

    import winternitz.signatures
    # Create signature and verify it with the same object
    wots = winternitz.signatures.WOTS()
    message = "My message in bytes format".encode("utf-8")
    sig = wots.sign(message)
    success = wots.verify(message=message, signature=sig["signature"])
    print("Verification success: " + str(success))
    # Output: Verification success: True

If you don't specify any values in the constructor of WOTS, it will use
the winternitz parameter 16 and the hash function *sha512* as default parameters.
The private key will be generated from entropy. After you received the public key,
either through ``wots.pubkey`` or inside the dict that is returned by the
``wots.sign(message)`` function call, you publish it. Verify that it was not modified.
In the best case a man-in-the-middle attack to modify your public key is impossible
by the design of the application. The last step is to publish your message and every
information in the dict that is returned by ``wots.sign(message)``, except the public
key (since it was already published). Publishing the fingerprint is optional, since it
is not essential for the signature verification. The signature dict contains the following
values:

.. code-block:: python

    {
        "w":            winternitz parameter (Type: int),
        "fingerprint":  message hash (Type: bytes),
        "hashalgo":     hash algorithm (Type: str),
        "digestsize":   hash byte count (Type: int),
        "pubkey":       public key (Type: List[bytes]),
        "signature":    signature (Type: List[bytes])
    }

With that data, another person can verify the authenticity of your message:

.. code-block:: python

    # Another person or machine wants to verify your signature:
    # get required hash function by comparing the name
    # published with local implementaitons
    if sig["hashalgo"] == "openssl_sha512":
        hashfunc = winternitz.signatures.openssl_sha512
    elif sig["hashalgo"] == "openssl_sha256":
        hashfunc = winternitz.signautres.openssl_sha256
    else:
        raise NotImplementedError("Hash function not implemented")

    wots_other = winternitz.signatures.WOTS(w=sig["w"], hashfunction=hashfunc,
                                            digestsize=sig["digestsize"], pubkey=sig["pubkey"])
    success = wots_other.verify(message=message, signature=sig["signature"])
    print("Verification success: " + str(success))
    # Output: Verification success: True

WOTSPLUS
--------
.. code-block:: python

    import winternitz.signatures
    wotsplus = winternitz.signatures.WOTSPLUS()
    message = "My message in bytes format".encode("utf-8")
    sig = wotsplus.sign(message)
    success = wotsplus.verify(message=message, signature=sig["signature"])
    print("Verification success: " + str(success))
    # Output: Verification success: True

If you don't specify any values in the constructor of WOTSPLUS, it will use the winternitz parameter
16 and the hash function defaults to *sha256*. It further requires a pseudo random function, which defaults
to *HMAC-sha256*, as well as a seed which is also generated from entropy. For further
informations about functions and their parameters, visit the module reference in
this documentation. Since WOTS+ uses a pseudo random function and a seed to derive signatures and public
keys, they have to be published as well. In addition to the signature of WOTS, the returned dict contains
the following values:

.. code-block:: python

    {
        # ...
        "prf":          pseudo random function (Type: str),
        "seed":         Seed used in prf (Type: bytes)
    }

Those arguments have to be specified in the constructor of WOTSPLUS in addition to those parameters
specified in WOTS.

Misc
----
The WOTS classes come with some features that will be explained in the following sections.

Fully configurable
~~~~~~~~~~~~~~~~~~
The WOTS classes are fully parameterizable. You can specify anything that is specified
in the papers describing the algorithm, including the Winternitz parameter, the hash function,
the pseudo random function (WOTSPLUS), the seed (WOTSPLUS), the private key and the public key.
specifing both a private key and public key results in the public key beeing discarded.

On-demand generation of keys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If no private key or no public key is specified, they will be set to None. The same
goes for the seed in wots+. Only when they are required, they will be generated or
derived. This means that as long as you don't execute ``repr(obj)``, ``str(obj)``, ``obj1 == obj2``,
``obj1 != obj2``, ``obj.pubkey``, ``obj.privkey``, ``obj.sign(...)`` or ``obj.verify(...)``, where obj is a
WOTS object, the keys will stay None.

Code representation of WOTS objects
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
You can call ``repr(obj)``, where obj is a WOTS object, to get a line of code which contains
all information to initialize another object so that it is equal to obj. Executing ``obj2 = eval(repr(obj))``
executes that code which is returned by ``repr(obj)`` and ultimately stores a copy of it in ``obj2``.

Human readable string representation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
You can call ``str(obj)`` to get a string which contains a human readable representation of that object.

Comparison of objects
~~~~~~~~~~~~~~~~~~~~~
You can compare two objects from this class ``obj1 == obj2`` and ``obj1 != obj2``

Optimizations
~~~~~~~~~~~~~
The code was carefully written to reduce execution times. It surely is not perfect and can still be optimized,
further time-critical sections could be coded as C extensions, but nevertheless in the current state it should
offer quite an efficient implementation. It defines ``__slots__`` to reduce execution times and storage requirements
within the class. Implementation of parallelization is planned, but it is only usefull when using huge winternitz
parameters, since python can only execute code in parallel if you spawn a new process and the overhead of forking
a new python interpreter is not negliable.
