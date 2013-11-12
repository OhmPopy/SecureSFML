SecureSFML is an extension to the SFML library (http://www.sfml-dev.org) which allows you to use encrypted tcp connections.

It is not an official SFML module !

BEWARE : it is not yet secure from Man In The Middle attacks : there's no authentication.
It just sets up an encrypted channel.

Supported Ciphers : 

AES-128-CBC
AES-192-CBC
AES-256-CBC
RC4 (with a patch that renews the keys on each packet using an IV)

=== How to install ===

As a prerequisite, you must have SFML 2.1 installed on your system already.
The OpenSSL lib is also necessary. (Ubuntu : # apt-get install libssl-dev)

== Linux ==

This project uses cmake, and this is what you need to do : 

$ cd SecureSFMLDirectory
$ mkdir build
$ cd build
$ cmake ../
$ make
$ sudo make install

Those commands will populate the SecureSFML include and lib directories with the SecureSFML module.

The associated shared library is called secure-sfml and should be linked using -lsecure-sfml

== Windows ==

Unfortunatly, there are no "easy" ways of installing this at the moment.
You need to import the source files in Visual C++ for example and link with the OpenSSL libs (libeay32.lib, ssleay32.lib)