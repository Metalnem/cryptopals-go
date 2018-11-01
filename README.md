# Matasano Crypto Challenges [![Build Status](https://travis-ci.org/Metalnem/cryptopals-go.svg?branch=master)](https://travis-ci.org/Metalnem/cryptopals-go) [![Go Report Card](https://goreportcard.com/badge/github.com/metalnem/cryptopals-go)](https://goreportcard.com/report/github.com/metalnem/cryptopals-go) [![license](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://raw.githubusercontent.com/metalnem/cryptopals-go/master/LICENSE)

Go solutions to the Matasano Crypto Challenges (<http://cryptopals.com/>). Solutions to the previous challenges are written in Erlang and can be found [here](https://github.com/Metalnem/cryptopals).

## [Set 4: Stream crypto and randomness](http://cryptopals.com/sets/4)

30. Break an MD4 keyed MAC using length extension ([problem](http://cryptopals.com/sets/4/challenges/30), [solution](https://github.com/Metalnem/cryptopals-go/blob/master/challenge30.go), [test](https://github.com/Metalnem/cryptopals-go/blob/master/challenge30_test.go))
31. Implement and break HMAC-SHA1 with an artificial timing leak ([problem](http://cryptopals.com/sets/4/challenges/31), [solution](https://github.com/Metalnem/cryptopals-go/blob/master/challenge31.go), [test](https://github.com/Metalnem/cryptopals-go/blob/master/challenge31_test.go))
32. Break HMAC-SHA1 with a slightly less artificial timing leak ([problem](http://cryptopals.com/sets/4/challenges/32), [solution](https://github.com/Metalnem/cryptopals-go/blob/master/challenge32.go), [test](https://github.com/Metalnem/cryptopals-go/blob/master/challenge32_test.go))

## [Set 5: Diffie-Hellman and friends](http://cryptopals.com/sets/5)

33. Implement Diffie-Hellman ([problem](http://cryptopals.com/sets/5/challenges/33), [solution](https://github.com/Metalnem/cryptopals-go/blob/master/challenge33.go), [test](https://github.com/Metalnem/cryptopals-go/blob/master/challenge33_test.go))
34. Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection ([problem](http://cryptopals.com/sets/5/challenges/34), [solution](https://github.com/Metalnem/cryptopals-go/blob/master/challenge34.go), [test](https://github.com/Metalnem/cryptopals-go/blob/master/challenge34_test.go))
35. Implement DH with negotiated groups, and break with malicious "g" parameters ([problem](http://cryptopals.com/sets/5/challenges/35), [solution](https://github.com/Metalnem/cryptopals-go/blob/master/challenge35.go), [test](https://github.com/Metalnem/cryptopals-go/blob/master/challenge35_test.go))
36. Implement Secure Remote Password (SRP) ([problem](http://cryptopals.com/sets/5/challenges/36), [solution](https://github.com/Metalnem/cryptopals-go/blob/master/challenge36.go), [test](https://github.com/Metalnem/cryptopals-go/blob/master/challenge36_test.go))
37. Break SRP with a zero key ([problem](http://cryptopals.com/sets/5/challenges/37), [solution](https://github.com/Metalnem/cryptopals-go/blob/master/challenge37.go), [test](https://github.com/Metalnem/cryptopals-go/blob/master/challenge37_test.go))
38. Offline dictionary attack on simplified SRP ([problem](http://cryptopals.com/sets/5/challenges/38), [solution](https://github.com/Metalnem/cryptopals-go/blob/master/challenge38.go), [test](https://github.com/Metalnem/cryptopals-go/blob/master/challenge38_test.go))
39. Implement RSA ([problem](http://cryptopals.com/sets/5/challenges/39), [solution](https://github.com/Metalnem/cryptopals-go/blob/master/challenge39.go), [test](https://github.com/Metalnem/cryptopals-go/blob/master/challenge39_test.go))
40. Implement an E=3 RSA Broadcast attack ([problem](http://cryptopals.com/sets/5/challenges/40), [solution](https://github.com/Metalnem/cryptopals-go/blob/master/challenge40.go), [test](https://github.com/Metalnem/cryptopals-go/blob/master/challenge40_test.go))

## [Set 6: RSA and DSA](http://cryptopals.com/sets/6)

41. Implement unpadded message recovery oracle ([problem](http://cryptopals.com/sets/6/challenges/41), [solution](https://github.com/Metalnem/cryptopals-go/blob/master/challenge41.go), [test](https://github.com/Metalnem/cryptopals-go/blob/master/challenge41_test.go))
42. Bleichenbacher's e=3 RSA Attack ([problem](http://cryptopals.com/sets/6/challenges/42), [solution](https://github.com/Metalnem/cryptopals-go/blob/master/challenge42.go), [test](https://github.com/Metalnem/cryptopals-go/blob/master/challenge42_test.go))
43. DSA key recovery from nonce ([problem](http://cryptopals.com/sets/6/challenges/43), [solution](https://github.com/Metalnem/cryptopals-go/blob/master/challenge43.go), [test](https://github.com/Metalnem/cryptopals-go/blob/master/challenge43_test.go))
44. DSA nonce recovery from repeated nonce ([problem](http://cryptopals.com/sets/6/challenges/44), [solution](https://github.com/Metalnem/cryptopals-go/blob/master/challenge44.go), [test](https://github.com/Metalnem/cryptopals-go/blob/master/challenge44_test.go))
45. DSA parameter tampering ([problem](http://cryptopals.com/sets/6/challenges/45), [solution](https://github.com/Metalnem/cryptopals-go/blob/master/challenge45.go), [test](https://github.com/Metalnem/cryptopals-go/blob/master/challenge45_test.go))
46. RSA parity oracle ([problem](http://cryptopals.com/sets/6/challenges/46), [solution](https://github.com/Metalnem/cryptopals-go/blob/master/challenge46.go), [test](https://github.com/Metalnem/cryptopals-go/blob/master/challenge46_test.go))
47. Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case) ([problem](http://cryptopals.com/sets/6/challenges/47), [solution](https://github.com/Metalnem/cryptopals-go/blob/master/challenge47.go), [test](https://github.com/Metalnem/cryptopals-go/blob/master/challenge47_test.go))
48. Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case) ([problem](http://cryptopals.com/sets/6/challenges/48), [solution](https://github.com/Metalnem/cryptopals-go/blob/master/challenge48.go), [test](https://github.com/Metalnem/cryptopals-go/blob/master/challenge48_test.go))

## [Set 7: Hashes](http://cryptopals.com/sets/7)

49. CBC-MAC Message Forgery ([problem](http://cryptopals.com/sets/7/challenges/49), [solution](https://github.com/Metalnem/cryptopals-go/blob/master/challenge49.go), [test](https://github.com/Metalnem/cryptopals-go/blob/master/challenge49_test.go))
50. Hashing with CBC-MAC ([problem](http://cryptopals.com/sets/7/challenges/50), [solution](https://github.com/Metalnem/cryptopals-go/blob/master/challenge50.go), [test](https://github.com/Metalnem/cryptopals-go/blob/master/challenge50_test.go))
51. Compression Ratio Side-Channel Attacks ([problem](http://cryptopals.com/sets/7/challenges/51), [solution](https://github.com/Metalnem/cryptopals-go/blob/master/challenge51.go), [test](https://github.com/Metalnem/cryptopals-go/blob/master/challenge51_test.go))

## [Set 8: Abstract Algebra](http://cryptopals.com/sets/8)

57. Diffie-Hellman Revisited: Small Subgroup Confinement ([problem](https://github.com/Metalnem/cryptopals-go/blob/master/challenge57.txt))
58. Pollard's Method for Catching Kangaroos ([problem](https://github.com/Metalnem/cryptopals-go/blob/master/challenge58.txt))
59. Elliptic Curve Diffie-Hellman and Invalid-Curve Attacks ([problem](https://github.com/Metalnem/cryptopals-go/blob/master/challenge59.txt))
60. Single-Coordinate Ladders and Insecure Twists ([problem](https://github.com/Metalnem/cryptopals-go/blob/master/challenge60.txt))
61. Duplicate-Signature Key Selection in ECDSA (and RSA) ([problem](https://github.com/Metalnem/cryptopals-go/blob/master/challenge61.txt))
62. Key-Recovery Attacks on ECDSA with Biased Nonces ([problem](https://github.com/Metalnem/cryptopals-go/blob/master/challenge62.txt))
63. Key-Recovery Attacks on GCM with Repeated Nonces ([problem](https://github.com/Metalnem/cryptopals-go/blob/master/challenge63.txt))
64. Key-Recovery Attacks on GCM with a Truncated MAC ([problem](https://github.com/Metalnem/cryptopals-go/blob/master/challenge64.txt))

## Useful links

1. [Bleichenbacher's RSA signature forgery based on implementation error](https://www.ietf.org/mail-archive/web/openpgp/current/msg00999.html) (challenge 42)
2. [The Debian PGP disaster that almost was](https://rdist.root.org/2009/05/17/the-debian-pgp-disaster-that-almost-was/) (challenge 43)
3. [DSA requirements for random k value](https://rdist.root.org/2010/11/19/dsa-requirements-for-random-k-value/) (challenge 44)
4. [Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1](http://archiv.infsec.ethz.ch/education/fs08/secsem/Bleichenbacher98.pdf) (challenges 47 and 48)
5. [Why I hate CBC-MAC](http://blog.cryptographyengineering.com/2013/02/why-i-hate-cbc-mac.html) (challenge 49)
6. [The CRIME attack](https://docs.google.com/presentation/d/11eBmGiHbYcHR9gL5nDyZChu_-lCa2GizeuOfaLU2HOU) (challenge 51)
