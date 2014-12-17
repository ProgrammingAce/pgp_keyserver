pgp_keyserver
=============

A purely python pgp/gpg keyserver

** Note: This project is not feature complete. It allows uploading and downloading of primary keys, but does not support features like sub-keys or key signing.

The main goal of this project is to improve search functionality beyond what the current alternatives offer. You can search by key fingerprint, email address, or name; you can use partial or full search strings. There is no limit to the number of search results that will be returned.

=== Getting Started ===

You will need to install the pgpdump python library - https://pypi.python.org/pypi/pgpdump

After that, you can just run the keyserver.py script: python2 keyserver.py
