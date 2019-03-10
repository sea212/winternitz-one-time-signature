Setup
=====
Requires: Python >= 3.4

| Install package: ``pip install winternitz``
| Install test tools: ``pip install winternitz[TEST]``
| Install linter (for tox tests): ``pip install winternitz[LINT]``
| Install documentation tools: ``pip install winternitz[DOCS]``
| Install everything: ``pip install winternitz[ALL]``

Test
----
| Without tox (no linter checks): ``python setup.py test``
| With tox: ``python -m tox``

Generate documentation
----------------------
``python setup.py docs``
