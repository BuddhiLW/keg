re-encrypt sealed nodes to the current recipients

The {{aka}} command decrypts a sealed node and encrypts it again to the recipients its tags select now. Use it after adding or removing a key in the `seal:` section of the `keg` file. `all` rekeys every sealed node. The hint is kept. Note that git history still holds the old ciphertext, readable by the old recipients.
