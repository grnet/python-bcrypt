#!/usr/bin/env python

# Copyright (c) 2006 Damien Miller <djm@mindrot.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# $Id$

import sys
try:
	from setuptools import setup, Extension
except ImportError:
	from distutils.core import setup, Extension
 
VERSION = "0.4"
 
if __name__ == '__main__':
	bcrypt = Extension('bcrypt._bcrypt',
		sources = [
			'bcrypt/bcrypt.c',
			'bcrypt/bcrypt_pbkdf.c',
			'bcrypt/bcrypt_python.c',
			'bcrypt/blowfish.c',
			'bcrypt/sha2.c',
			'bcrypt/timingsafe_bcmp.c',
		],
	)
	setup(	name = "py-bcrypt",
		version = VERSION,
		author = "Damien Miller",
		author_email = "djm@mindrot.org",
		url = "https://code.google.com/p/py-bcrypt",
		description = "bcrypt password hashing and key derivation",
		long_description = """\
py-bcrypt is an implementation the OpenBSD Blowfish password hashing
algorithm, as described in "A Future-Adaptable Password Scheme" by 
Niels Provos and David Mazieres and related bcrypt-based key derivation
function implemented in OpenBSD libutil.

This system hashes passwords using a version of Bruce Schneier's
Blowfish block cipher with modifications designed to raise the cost
of off-line password cracking. The computation cost of the algorithm 
is parametised, so it can be increased as computers get faster.

Two interfaces are supported: a classic password hashing interface and
a key derivation function (KDF) intended for generating cryptographic
keys.
""",
		license = "BSD",
		packages = ['bcrypt'],
		ext_modules = [bcrypt]
	     )

