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
    wots = winternitz.signatures.WOTS()
    sig = wots.sign(b"My message in bytes format")
    success = wots.verify(sig["signature"])
    print("Verification success: " + str(success))

If you don't specify any values in the constructor of WOTS, it will use
the winternitz parameter 16 and the hash function *sha512* as default parameters.
The private key will be generated from entropy.

WOTSPLUS
--------
.. code-block:: python

    import winternitz.signatures
    wotsplus = winternitz.signatures.WOTSPLUS()
    sig = wotsplus.sign(b"My message in bytes format")
    success = wotsplus.verify(sig["signature"])
    print("Verification success: " + str(success))

If you don't specify any values in the constructor of WOTSPLUS, it will use the winternitz parameter
16 and the hash function defaults to *sha256*. It further requires a pseudo random function, which defaults
to *HMAC-sha256*, as well as a seed which is also generated from entropy. For further
informations about functions and their parameters, visit the module reference in
this documentation.

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
