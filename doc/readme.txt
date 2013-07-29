Krypto - a file encrypter/decrypter based on the Frog algorithm.

Copyright (c)2001-2003 Daniel de Kok, read the source files for licensing
and non-warranty information.

* Introduction *

Thank you for your interest in Krypto! Krypto is a file encrypter/decrypter
OS/2 and eComStation that uses the public domain Frog algorithm. At
the moment it uses Frog in CBC mode with a 256-bit key, but it can easily be
modified to use keys up to 1000-bit (contact me if you need a version with
support for larger keys than 256-bit). Please start krypto with the -h flag
for usage information.

* Krypto usage *

Syntax:

Encryption: krypto -e <infile> <outfile> [key]
Decryption: krypto -d <infile> <outfile> [key]

If no key is specified Krypto will ask you (interactively) for a key. If you
want your data to be secure, please use keys longer than 8 characters. Shorter
keys can quickly be regained using 'brute-force' (meaning a cracker tries every
possible combination).

Samples:

krypto -e report.txt report.txt.crypted 3Dwk[7GeJF3fAS:k -> encrypts report.txt
using the key "3Dwk[7GeJF3fAS:k" and the encrypted file is named
report.txt.crypted.

krypto -d case10.crypted case10.doc -> decrypts case10.crypted to case10.doc,
krypto will ask you for a key.

* Todo *

- Extensive testing. Can somebody test the Frog-based version on Win32?
- Double the number of iterations of the Frog cypher. Doing so currently breaks
  decryption.
- Write a GUI front-end for OS/2 (done, currently being tested).
- An option that allow you to read a key from a file.
- Write a random key generator.

* Thanks *

Thanks go out to the following people:

- Tecapro for the Frog algorithm

* Feedback *

Please send comments, bug-reports and other feedback to
daniel@evilbsd.net. Feedback is appreciated, even a message telling
me it works fine on your computer.

* History *

Version 0.41:
        - Fixed a wrongly placed I/O check.
        - Bumped the keylength to 256-bit.

Version 0.40:
        - Replaced the icon with a 40x40 icon. This looks much better.
        - Moved the buffer encryption/decryption code from the VIO
          dependend EncryptFile/DecryptFile to seperate procedures.
          The frogcrypt unit is now completely independent of VIO
          and PM code.
        - Replaced assembler code, making Krypto more or less platform
          independend.

Version 0.31:
        - Added a progress indicator.
        - Better documentation, readme.txt now includes useful examples.
        - Fixed some minor bugs.

Version 0.3:
        - Completely rewrote Krypto. I am now using the public domain
          Frog block cipher. Frog is a new algorithm (1998), and was
          a candidate for AES. I chose Frog and not Blowfish or Rijndael,
          because the Frog implementation is written in very clean Pascal.
          File I/O is now handled by blockread and blockwrite instead of
          read/write, so I/O performance is much better right now.

Version 0.02:
        - Added non-interactive support.
        - Fixed StringToBlock (fills remaining bytes with spaces).
        - Added history.txt.
        - Better structured parameter reading.
        - Misc. bugfixing.

Version 0.01:
        - Initial version using DES cipher.
