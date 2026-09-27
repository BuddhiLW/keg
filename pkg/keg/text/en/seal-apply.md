seal every note whose front matter asks for it

The {{aka}} command seals, in place, every plaintext node whose front matter carries a `seal:` directive (see {{cmd "seal"}}), and updates the index so only the public hint remains. It runs automatically before every publish; use it directly to seal without publishing, e.g. before a manual `git commit`.
