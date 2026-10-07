#Part1
Part 1.1
 -pbkdf2 takes the plain text passkey that the user sets, and reconfigures it into a set of random bits and pass it on to aes. Doing so is crucial to the security of the encryption because human passphrases tend to not be random and contain coherent thought/repititions. 
Part1.2
 They generate different checksums because each time the message is encrypted a random string of data is inserted thus generating a different hash. Having different IV's is important because otherwise a hacker could tell that 2 files contained the same text, which could open them up to cross referencing and pattern recognition  since identical texts would yield identical ciphertexts.
Part 1.3
	1. ECB produces 3 distinct blocks, whereas CBC produces 37, each distinct. Of the 3 distinct blocks, the most common is repeated 24 times.
	2. Despite not leaking the contents of the file, ECB did leak certain patterns within the text such as certain types of repeating/identical ciphertext. The illumination of these patterns in turn allow them to observe the data structure and potentially use pattern analysis to figure out the contents
	3. Does that mean you are using ECB or CBC? The answer is important because the flawed protection ECB offers would easier allow a hacker to gain certain bits of information by crossrefercing the blocks of data 
#Part2
Part 2
	1. Hashing just preserves the integrity of the file, meaning if someone tampered with it you could compare the previous hash to verify a difference. The issue however is that if the bad actor controls the channel, they could simply intercept the file and hash, edit it, generate a new hash of their own, and then send it to you. Hashing alone does nothing to verify who authored the file.
	2. HMAC on the other hand not only proves the integrity of the file, but also the authentication, since you and your partner have to use the same password to get the same output. 
	3. Provided their ability to intercept files sent between the parties, the hacker can do basically anything with the provided only a SHA-256 is used. As explained earlier, they would be able to modify the file and trick the recipient rather easily into accepting it/misleading them into believing that they are not who they say they are. Alternatively with an HMAC, while the hacker would be able to read/modify the file, they wouldn't be able to trick the recipient into accepting it/believing them to be someone else.
#Part 3
	1. It proves that whoever generated the key did so with access to my email, it however does not verify that it was specifically me.
	2. Confirming with the classmate offline ideally, or perhaps over call/other form of communication would help verify including maybe a mutual friend would help the process. That way you could confirm the generated key securely(compare the output using gpg --fingerprint with their known fingerprint, as a attacker wouldn't be able to replicate their unique hash based of the key) outside the external survailance/tampering
#Part 4
	1. The first packet contains the encryption key that was generated, the second is the encrypted text. 
	2. RSA is slower and unable to encrypt larger files(ie those that contain gigabytes of data/are bigger than the key itself). It therofore only uses RSA for the session key
	3. Hybrid cryptography(in this case public key encyrption and computer encryption)
Part 4.3
	1. You sign with your private key
	2. You verify with your public key
	3. It is encrypted with the recipients public key
	4. And decrypted with the recipients private key 	
	2) Signing provides authenticity to whatever is sent because it holds your personal key, and is therfore uniquely yours and nonrepudible. Encryption largely just provides confidentiality, but anyone with your public key can encrypt it.

#Part 5
	1. Ed25519 uses a harder mathmatical process than what RSA uses(eliptical curve vs prime factorization). This added difficulty to crack means it's not necessarily weaker despite the shorter length.

#Part 7

Part 7.2
	1. The program doesn't require any password length. Also since the salt is stored with the file, an attacker who manages to copy it basically has every input BUT the password.  The key may have alot of possibilities but the attacker only needs to iterate through a list of common passwords. There is also no block on this, as they are allowed infinite offline guesses. This kinda follows the same flaw as the Ceaser Cipher, since, while it may seem like they have a lot of potential keys to guess, the key space is a much smaller set of something a human would actually create(a list that is narrowed by not enforcing guidlines of password length checks).
	2. While GCM does mantain confidentiality through its encryption, the fact that the code passes None as the associated_data argument means that a file's tag only proves that the ciphertext is valid under this password, not that it is the specific file or version the user expects. While this may not help them break it, this flaw would allow attacker to swap/revert copies. As such, while the program may fufill one of the main 3 requirements(confidentiality) it doesn't prove perfect in protecting the files identity/version(integrity)
	3. The output will always be 44 bytes bigger than the input, which reveals details about the exact size(a practice which we discouraged when discussing ECB's tendency to preserve a files 'structure'), which may not help them break it, but coud aid them in recognizing a known document by its exact size, or tell a short note apart from a large spreadsheet.

Part 7.3
        1. Common/Passwords shorter than 14 chars/<5 distinct characters are rejected before encyrption. Key is derived from the password so the pass sets the size the attacker needs to search. This addresses the first problem by making the password harder to crack
        2. Files now start with headers, and pass a context label which is passed into associated data instead of none to prevent tampering. This addresses problem 2 and prevents potential file swapping, since the additional context verifies. Recording the iteration count also means you can raise it later without breaking older files.
        3. Before encryption the the plaintext gets an 8-byte length prefix and is padded with zeros to some multiple of 4,096 bytes, and as such no longer reveals the exact plain text file(tho this does make them longer). This addresses problem 3 

