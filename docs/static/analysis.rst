.. _analysis:

Analysis & Overview
=====================

In this section we review the security profile of CryptX to allow the more technically-minded among our users to appreciate the effort put into making this library as secure as possible. Where necessary, algorithm constructions are documented for peer review. It is also noteworthy that this library is an open-source project. Therefore the entire code base is available on Github. Additionally, methods used to improve side-channel resistance are also presented for peer review. This section is live-updated as more information becomes available.

Secure RNG Construction and Analysis
-------------------------------------

Rationale & Difficulties
^^^^^^^^^^^^^^^^^^^^^^^^^

The first question to answer in the quest to devise a secure RNG was: Does the TI-84+ CE produce randomness, and if so, (1) what is the nature of this randomness (does it have entropy?) and (2) how does this differ by hardware revision? The calculator is unlike a computer in that it lacks many of the dynamic sources of entropy that go into generating randomness for those platforms. It was intially intended to use the r register or CPU clock cycle counter, but this was rapidly discarded after the discovery that both of those are predictable. At a loss, and with insufficient knowledge of the device hardware mechanics, I posted on Cemetech seeking information about possible sources of randomness on the TI-84+ CE. Cemetech user Zeroko came to the rescue with data on hardware bus noise.

	`SRAM has a pair of bitlines for each bit of each column address, which are connected to a circuit that tries to make them both be charged to an equal, high level before reading from a memory cell (which partially discharges one of the two) and to a sense amplifier (basically a comparator) to read the resulting state afterward. (There may also be another level of gating between the bitlines and the comparators, but that does not strongly affect the dynamics.) In the unmapped space, there are no memory cells, so the controller equalizes the bitlines however well it does, then does nothing (there being no memory cell to discharge them), then senses which bitline is at a higher level. For some column addresses, this will be heavily biased one way or the other because the pre-charge transistors on the bitlines are too different, while for others, it will be less biased because they are more similar.`
	
Source-Selection Algorithm
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Based on statistical analysis of the unmapped space, it became clear that there was a very large subset of possible source bytes that appeared entropic and that these subsets differed by hardware revision. After some discussion an algorithm was constructed (with optimization support from Adam Beckingham) that would poll each byte in the unmapped space 1024 times and then count the deviation.

As the algorithm proceeds through the unmapped space, it maintains an internal pointer to the most entropic source it has encountered as well as a value to beat on the degree of deviation. If the algorithm encounters a better source, it updates the internal pointer and the value to beat. By the time the algorithm finishes polling the unmapped space, it will have selected the best possible source of entropy. That source address is retained by the library for use gathering entropy and cannot be modified by the user. Should the algorithm fail to find a suitable source (the maximum allowable bias is 75%/25% in either direction), the initialization function will return FALSE.

Entropy-Pooling & Mitigating Bias/Correlation in the Source
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The RNG internally reserves an entropy pool 119 bytes large in the device’s accelerated RAM. 119 bytes was chosen because it fits nicely within two (2) SHA-256 blocks. To generate a random number, each byte in the entropy pool is updated by reading from the selected source byte. The entire pool is then passed through the SHA-256 cryptographic hash, generating a 32-byte digest. That hash is broken into 8-byte blocks, each byte of which is XORed together to produce a single byte. The result is a 4-byte compression of the 119-byte entropy pool.

Due to the nature of the CE hardware, there is a measurable correlation in the values of floating bits within unmapped memory. This correlation varies depending on the sample size, but would measurably reduce the entropy of the system. While specific numbers on the degree of correlation are, as of yet, unavailable, we do know that there are higher amounts of correlation in the initial reads which decreases after a certain number of reads. Zeroko provided a more technical explanation of this as well.

	`Another source of non-randomness distinct from the bias is that the bitlines act like capacitors, so precharging only moves their voltage toward the desired level rather than reaching it. This results in a correlation between reads, with the correlation getting weaker with a longer time interval between them and with more intervening reads performed. This is why we cannot just use a von Neumann extractor (which only de-biases) and instead have to do something like XORing many consecutive bits together (which does not fully remove the bias and correlation but can lower it to an undetectable level).`
	
To solve this problem, Zeroko performed some analysis on the unmapped memory and revealed that XORing seven (7) reads together per byte would be sufficient to trend the actual entropy closer to what is calculated above.

Proof of Cryptographic Strength
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In order to be secure (at least on paper), a PRNG has to pass 2 distinct additional unpredictability assessments in addition to the requirement that it also pass general statistical randomness tests (which this generator does for sufficient sample sizes). The two additional tests are the next-bit test and the state compromise test.

**Next-Bit Test**:
	
	The Next-Bit Test is defined as follows: given the prior output of the PRNG, the next bit of the output cannot be predicted by a polynomial-time statistical test with a probability non-negligibly greater than 50%.
	
	To prove this is the case here we need to evaluate the entropy of the selected source. As the entropy varies depending on what bit is selected, we will compute the entropy of the worst-case to keep things simple and take that as the minimum effective entropy of the generator. The worst-case this generator will allow is the set of probabilities P = {0.75, 0.25}. This means that a bit will be set 75% of the time and reset the rest of the time or vice versa.
	
	.. prf:proof:: **Entropy for Worst-Case Source**
		
		*We will use the Shannon entropy formula to prove that the generator produces sufficient entropy to satify entropy requirements for random artifacts.*
		
		.. math::
			H(bit) = \sum_{i=1}^n P(i) * \log_2 \frac{1}{P(i)}
			
		where:
			| n = length of the set of probabilities,
			| P (i) = probability of the i-th element in the set.
			
		With probability P = {0.75, 0.25}, it follows that:
		
		.. math::
			H(bit) = 0.75 * \log_2 \frac{1}{0.75} + 0.25 * \log_2 \frac{1}{0.25} = 0.81
			
		We will hand-wave the other bits in the selected source by just assuming no entropy (although in reality, there will probably be some entropy scattered throughout the rest of the byte as well). This means that the total entropy of the selected byte equals that of the bit calculated above.
		
		Multiply the bytewise entropy by the byte-length of the entropy pool (119) to compute the entropy derived by populating the entropy pool from the source.
		
		.. math::
				H(pool) = 0.81 * 119 = 96.4
			
		This is the number of bits of entropy produced per 32-bit object generated. In order to be secure, a random artifact must have entropy equivalent to or exceeding the bit-width of the generated artifact. For example, a 256-bit key should contain 256 or more bits of entropy. This generator satisfies that constraint.
			
**State Compromise Test**:

	The State Compromise Test simply means that an adversary that somehow gains knowledge of the generator’s state remains unable to predict its output. This means that deterministic generators that have their outputs influenced by some seed value are not suitable for cryptography unless the output incorporates sufficient entropy.
	
	The RNG in CryptX does not use a seed value at all, instead relying entirely on entropy for its output. The only state it maintains is the byte initially selected as the source of entropy. However, because the source has sufficient entropy, an attacker who knows what bit is being used to gather entropy still should be unable to reconstruct the output stream with probability non-negligibly higher than 50% per bit of output.
	
	Another consideration is runtime state manipulation. The TI-84+ CE is not a multitasking-capable processor, therefore the device can only process one code path at a time. This removes vulnerability to local state manipulation (changes to state by other code running on the device). Additionally, the library halts system interrupts while the random number generation code is running, which halts system USB activity. This renders state manipulation via that method impossible as well.

The previous stated, I assert that the generator satisfies all algorithmic constraints for cryptographic security and is thus safe for use as a cryptographic RNG.

**Note that these proofs only apply to physical hardware (an actual TI-84+ CE), not to emulators.** Due to the inability of an emulator to accurately reproduce the behavior of the unmapped region, they implement a deterministic RNG to create the illusion of randomness for that range of memory. This yields statistical randomness with an obscurity factor due to how CryptX selects the source, but the randomness is still not cryptographically secure. Bear this in mind when using CryptX from an emulator.


Side-Channel Analysis
----------------------

It has been quite difficult to implement this library with side-channel resistance due to the nature of the hardware, for a number of reasons including the speed of the processor (or more accurately, relative slowness of the processor) and overall design of the device's hardware and software. For example, the calculator provides SHA hardware but locks it, meaning the only way for a developer to access it is through an exploit and a Flash unlock. A CPU implementation is therefore more *secure*, but also more vulnerable to timing inconsistencies. There are a number of similar issues that make implementing cryptography difficult on this platform but then again, this is a calculator. It was intended for math class, not encrypting stuff over a network.

This being said I will submit that Texas Instruments should take notice of the degree of innovation the development community has achieved with these devices and therefore take the requisite steps to make implementing cryptography properly on their platform more feasible. By this I don't mean going so far as adding cryptographic hardware acceleration (that isn't really necessary), but stop declaring things relevant to security *proprietary* when they are not (if you need to hide your security mechanisms behind a wall of secrecy, you aren't doing security right), stop trying to stifle access to ez80 assembly and C programming (this is just going to make more people want to look for vulnerabilities), and release developer documentation that is actually helpful. The lack of any real community engagement from TI means we have to run on the basis of statistical analysis, reverse-engineering, and implement-and-pray. That's no way to have a secure platform.

Timing-Safe Implementations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

One of the first considerations taken within this library (and also the hardest for the reasons stated above) was developing with resistance to timing analysis. A simple definition of what timing analysis means (for those who do not know) is an attacker attempting to break an algorithm by analyzing differences in execution time. On a platform as slow as the TI-84+ CE, timing-resistance is very hard to counterbalance with efficiency.

A timing analysis review of the entire library is in progress and details will be posted below as they are available.

| **RSA**: Modular exponentiation is constant-time if run from normal speed memory.
| **Elliptic Curve Diffie-Hellman**: Underlying Galois field arithmetic implemented constant-time to the best extent possible.
| **Advanced Encryption Standard**: Timing analysis reveals data length, or for CBC mode, nearest block length of data. This should not defeat the implementation.
| **Digest Comparison**: Implementation is constant-time.
| **Secure RNG, Source Selection**: analysis pending
| **Secure RNG, rand generation**: analysis pending
| **SHA-256**: analysis pending

Stack Cleanup
^^^^^^^^^^^^^

Another consideration taken is to avoid leaving residual computational data in the stack frame after a function that performs data transformations completes. For this reason, some code was written that purges the stack frame and we call that code in most of the user-facing encryptor functions before returning control to the caller. For reference, the code used to accomplish this is:

.. code-block::

	?stackBot := 0D1987Eh
	stack_clear:
	; backup hl, a, and e
		ld (.smc_a), a
		ld (.smc_hl), hl
		ld a, e
		ld (.smc_e), a
		; set from stackBot + 4 to ix - 1 to 0
		; ix points to the current top of stack frame
		lea de, ix - 2
		ld hl, -(stackBot + 3)
		add hl, de
		push hl
		pop bc
		lea hl, ix - 1
		ld (hl), 0
		lddr
		; restore a, hl, e
		ld e, 0
		.smc_e:=$-1
		ld a, 0
		.smc_a:=$-1
		ld hl, 0
		.smc_hl:=$-3
		ld sp, ix
		pop ix
		ret

Halting System USB Activity
^^^^^^^^^^^^^^^^^^^^^^^^^^^

After resolving buffer leaks, our attention turned to thwarting attempts to map the device’s memory while sensitive operations are running to gain information about the encryption or decryption. While there is sufficient difficulty in achieving this on this device, I believe the solution arrived at is sufficient.

It is the system interrupt that makes it possible for the operating system to handle activity on the USB port, and disabling said interrupts would severely hamper attempts to read CryptX’s operating state by preventing the system from responding to USB activity. For this reason, some code was written that disables interrupts in all functions where data is being encrypted or decrypted, or nonces are being generated, saving the previous interrupt state to SMC, and restoring that state afterwards. While there are many variations of this code that operate in slightly different ways depending on when they are called, here is the basic version of it, for reference:

.. code-block::

	; helper macro for saving the interrupt state, then disabling interrupts
	macro save_interrupts?
		ld a,i
		push af
		pop bc
		ld (.__interrupt_state),bc
		di
	end macro

	; helper macro for restoring the interrupt state
	macro restore_interrupts? parent
		ld bc,0
		parent.__interrupt_state = $-3
		push bc
		pop af
		ret po
		ei
	end macro

Algorithmic Security
----------------------

This section describes considerations for resistance to **chosen plaintext** and **chosen ciphertext** attacks. An encryption system is vulnerable to these types of attacks if the attacker can submit arbitrary plaintexts for encryption or ciphertexts for decryption and receive predictable output. These attacks can be used to reveal the encryption secret for the session.

Chosen Plaintext Attack
^^^^^^^^^^^^^^^^^^^^^^^

Defense to *chosen plaintext attack* involves a cipher's output being indistinguishable from truly random output.

	- **AES**: Proper nonce handling. Generate a securely-random, unique nonce for each session or message as dictated by cipher mode constraints. See `NIST Special Publication 800 <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf>`_ for recommendations for ensuring nonce uniqueness.
	- **RSA**: The *optimal asymmetric encryption padding v2.2* scheme includes a random string in the encoding prior to encryption.
	- **ECDH**: Elliptic Curve Diffie-Hellman is a key negotiation protocol, not an encryption system, so considerations are slightly different. Choose a unique private key when using ECDH to negotiate a new session key for AES.


Chosen Ciphertext Attack
^^^^^^^^^^^^^^^^^^^^^^^^^

Defense to *chosen ciphertext attack* involves the inclusion of an authentication tag with the outgoing message so that the message can be verified prior to decryption.

	- **AES**:
		- *Recommended* - Use Galois Counter mode. With this cipher mode you can generate an authentication tag from the cipher that is secure under the given session key. Append that tag to the outgoing message. Ensure proper nonce handling for GCM mode. Generate a new nonce for the session after returning a tag. GCM has a nasty tag forgery vulnerability if this is not ensured. *Some cryptographers will discourage the use of GCM mode due to the forbidden attack in favor of other cipher modes. CryptX currently supports no other authenticating cipher modes, so for the time being use GCM with proper nonce handling.*

		- *Alternate* - Use CBC or Counter modes. Encrypt the plaintext and then generate a hash or HMAC of the ciphertext. Append the digest to the outgoing message.
	
	- **RSA**: The system is encryption only, so any CCA protections would be on the part of the server-side library you are using.
