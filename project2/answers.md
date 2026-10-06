Part 1.1
 -pbkdf2 iterates over the password and hashes it, with the "-salt" inserting a random string of data to make it harder to interpret. A passphrase is nessecary because without it anybody could decrypt the encrypted file, and access the password
Part1.2
 They generate different checksums because each time the message is encrypted a random string of data is inserted thus generating a different hash. This is important because otherwise a hacker could tell that 2 files contained the same password, which could open them up to dictionary cross referencing since identical texts would yield identical ciphertexts.
Part 1.3
	1. ECB produces 3 distinct blocks, whereas CBC produces 18. Of the 3 distinct blocks, the most common is repeated 12 times.
	2. Despite not leaking the contents of the file, ECB did leak certain patterns within the text such as certain types of repeating/identical ciphertext. The illumination of these patterns in turn allow them to observe the data structure and potentially use pattern analysis to figure out the contents
	3. Does that mean you are using ECB or CBC? The answer is important because the flawed protection ECB offers would easier allow a hacker to gain certain bits of information by crossrefercing the blocks of data 
Part 2
	1. Hashing just preserves the integrity of the file, meaning if someone tampered with it you could compare the previous hash to verify a difference. The issue however is that if the bad actor controls the channel, they could simply intercept the file and hash, edit it, generate a new hash of their own, and then send it to you. Hashing alone does nothing to verify who authored the file.
	2. HMAC on the other hand not only proves the integrity of the file, but also the authentication, since you and your partner have to use the same password to get the same output. 
	3. Provided their ability to intercept files sent between the parties, the hacker can do basically anything with the provided only a SHA-256 is used. As explained earlier, they would be able to modify the file and trick the recipient rather easily into accepting it/misleading them into believing that they are not who they say they are. Alternatively with an HMAC, while the hacker would be able to read/modify the file, they wouldn't be able to trick the recipient into accepting it/believing them to be someone else.
Part 3
	1. It proves that whoever generated the key did so with access to my email, it however does not verify that it was specifically me.
	2. Confirming with the classmate offline ideally, or perhaps over call/other form of communication would help verify. Having a middleman would also help the process
Part 4
	1. The first packet contains the encryption key that GPG generated, the second is the encrypted text. 
	2. RSA is slower and unable to encrypt larger files(ie those that contain gigabytes of data). It therofore only uses RSA for a small portion of the key
	3. Hybrid cryptography(in this case public key encyrption and computer encryption)
Part 4.3
	My personal Key
	1. BC722950391E5F4C
	2. BC722950391E5F4C
	The encryption key
	3. A4D374B63691153E
	4. A4D374B63691153E
	
	2) Signing provides authenticity to whatever is sent because it holds your personal key, and is therfore uniquely yours and nonrepudible. Encryption largely just provides confidentiality, but anyone with your key can encrypt it.

Part 5
	1. Unlike GPG, Ed25519 utilizes a harder mathmatical process than what RSA uses(eliptical curve vs prime factorization). This means it's not necessarily weaker despite the shorter length.

Part 7
	1. The program doesn't require any password length, and the salt is written in the beginning meaning the encryption is only as strong as the password(if they have the file they only need to iterate through a list of common passwords). There is also no block on this, as they are allowed infinite offline guesses. This kinda follows the same flaw as the Ceaser Cipher, since, while it may seem like they have a lot of potential passwords to guess, the key space is a much smaller set(the password)
	2. The codes utilization of AES-GCM for both confidentiality and integrity raises a few issues. While it does mantain confidentiality through its encryption, the fact that the code passes None as the associated_data argument means that a file's tag only proves that the ciphertext is valid under this password, not that it is the specific file or version the user expects. While this may not help them break it, this flaw would allow attacker to tamper/revert copies. This relates to the point about the importance of using seperate measures for the big 3, as while the message's integrity is protected its headers aren't
	3. The output will always be 44 bytes bigger than the input, which reveals details about the exact size(a practice the lectures caution against), which might help someone recognize a known document by its exact size, or tell a short note apart from a large spreadsheet.

7.3
    1. Common/Passwords shorter than 14 chars/<5 distinct characters are rejected before encyrption. Key is derived from the password so the pass sets the size the attacker needs to search. This addresses the first problem by making the password harder to crack
    2. Files now start with headers, and pass a context label which is passed into associated data instead of none to prevent tampering. This addresses problem 2 and prevents potential file swapping, since the additional context verifies. Recording the iteration count also means you can raise it later without breaking older files.
    3. Before encryption the the plaintext gets an 8-byte length prefix and is padded with zeros to some multiple of 4,096 bytes, and as such no longer reveals the exact plain text file(tho this does make them longer). This addresses problem 3 
