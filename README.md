pgp_keyserver

=============

A purely python pgp/gpg keyserver

** Note: This project is not feature complete. It allows uploading and downloading of primary keys, but does not support features like sub-keys or key signing.

The main goal of this project is to improve search functionality beyond what the current alternatives offer. You can search by key fingerprint, email address, or name; you can use partial or full search strings. There is no limit to the number of search results that will be returned.

=== Getting Started ===
=============

You will need to install the pgpdump python library - https://pypi.python.org/pypi/pgpdump

After that, you can just run the keyserver.py script: python2 keyserver.py

=== Limitations ===
=============

This server works well for uploading and downloading keys using any PGP applications we've tested it with, but there are several key features that are still missing.

* There is no support for sub-keys
* You cannot remove or modify keys once added to the database
* Since you can't modify keys, you can't use this server for key signing

