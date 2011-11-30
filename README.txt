SecureSFML is an extension to the SFML library (http://www.sfml-dev.org) which allows you to use encrypted tcp connections.

=== How to install ===

As a prerequisite, you shall have SFML installed on your system already.
The OpenSSL lib is also necessary.

== Linux ==

This project uses cmake, and this is what you need to do : 

cd SecureSFMLDirectory
mkdir build
cd build
cmake ../
make
sudo make install

Those commands will populate the SFML include and lib directories with the SecureSFML module.

The associated shared library is called sfml-network-secure and should be linked using -lsfml-network-secure

== Windows ==

Unfortunatly, there are no "easy" ways of installing this at the moment.
