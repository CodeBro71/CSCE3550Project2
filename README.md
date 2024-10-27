This is my submission for CSCE3550 project 2. Despite getting full marks with the blackbox testing, for some reason my own test suite is unable to decode the jwts with the public rsa key. I think this may have to do with the fact that the private key used to sign the jwt is being read from the database and is somehow altered in the serialization/loading process. However, in my debugging I found that the loaded key was identical to the key created before serialization and storage. So one would assume that the public key should work, but jwt.decode() still throws the "Signature verification failed" exception. Therefore the true reason still alludes me :(
