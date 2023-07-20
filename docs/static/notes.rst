.. _closingnotes:

Closing Notes
===============

CryptX is a work in progress and sees regular updates that add resistance to various forms of attack. While its algorithmic security is solid if implemented properly, there are weaknesses in the hardware of the device that make a full security evaluation of the library difficult. For this reason, use CryptX only for low-risk applications...logging in to game servers, custom secure services for calculators, and similar. You should not be sending anything requiring true security using a calculator.

If you have any questions about the proper usage of CryptX in your programs, any of its functionality, algorithms, etc, please do not hesitate to contact me on Discord at NefariousArcher. I would rather you ask questions than implement security improperly and risk compromising your implementation. I also enjoy discussing and learning about cybersecurity in general.

Please update to new stable releases as soon as they become available and update any software you are developing to use the latest versions of CryptX as soon as you are able. At this stage in development, updates are usually security enhancements, not major feature additions.

Special thanks to the following individuals who contributed materially to the project:

+-----------------------+-----------------------------------------------+
| Role                  | Contributor                                   |
+=======================+===============================================+
| Lead Developer        | Anthony Cagliano                              |
+-----------------------+-----------------------------------------------+
| C->Assembly Rewrite   | Adam Beckingham                               |
+-----------------------+-----------------------------------------------+
| Code Contributions    | | John Caesarz                                |
|                       | | jacobly                                     |
|                       | | Zeroko                                      |
|                       | | calc84maniac                                |
+-----------------------+-----------------------------------------------+
| Info & Analysis       | | Zeroko                                      |
|                       | | MateoC "That's not how RSA works you idiot!"|
+-----------------------+-----------------------------------------------+
| QA & Testing          | null                                          |
+-----------------------+-----------------------------------------------+

Other References
-----------------

	- https://github.com/B-Con/crypto-algorithms/
		*Source of ported AES and SHA-256 algorithms.*

	- https://github.com/kokke/tiny-ECDH-c
		*Source of reference ECDH implementation.*
	
	- https://datatracker.ietf.org/doc/html/rfc4868
		*SHA-256 HMAC implementation details.*

	- https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
		*AES-GCM implementation details.*
		
	- Modern Cryptography and Elliptic Curves, A Beginner’s Guide, Thomas R. Shemanske.
		*Reference for learning elliptic curves.*
		
License
--------

This software is released under the terms of the GNU General Public License Agreement v3.0. To sum a stupidly long document into something short enough that people might actually read it: You can do whatever you want with the source code to this project so long as you don’t stop anyone else from doing whatever they want with it. What does this mean? You can use the source code in your own stuff (called derived work) in all or in part or even modified but you cannot supersede the open source license on derived components, pursue claims of infringement against other developers for their own utilization of our code, or pursue liability claims against this project for your use of our code.
