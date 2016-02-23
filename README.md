## SPHINCS in Python [![Build Status](https://travis-ci.org/joostrijneveld/SPHINCS-py.svg?branch=master)](https://travis-ci.org/joostrijneveld/SPHINCS-py) [![Coverage Status](https://coveralls.io/repos/joostrijneveld/SPHINCS-py/badge.svg?branch=master&service=github)](https://coveralls.io/github/joostrijneveld/SPHINCS-py?branch=master)

This repository contains an implementation of the hash-based signature scheme [SPHINCS](http://sphincs.cr.yp.to/), in Python. The goal for this implementation was not to be fast, secure, or in any other way useable in a production environment. This cannot be stressed enough. **DO NOT USE THIS** for any signature that you or others rely on in any way.

Instead, this code was written to aid in understanding of the SPHINCS scheme, and to make it easier to experiment with the individual parts. The main aim was for the code to be flexible and (to some extent) readable.

#### Third party code

This project relies on the [Python implementation of BLAKE](http://www.seanet.com/~bugbee/crypto/blake/), by Larry Bugbee. This code was optimised for speed, but it is considered out of the scope of this repository to re-implement BLAKE from scratch.

### Using this code

In order to be able to run the code, make sure the requirements listed in `requirements.txt` are satisfied. This can be achieved by calling `pip install -r requirements.txt`

The `SPHINCS.py` can be called as an executable, according to the commandline interface specified below. Note again that this implementation is not optimised for speed - it takes some time to produce a signature using the default SPHINCS-256 parameters.

```
Usage:
    SPHINCS.py keygen [--secret-key FILE] [--public-key FILE]
    SPHINCS.py sign [-m FILE|--message FILE] [--secret-key FILE] [-s FILE|--signature FILE]
    SPHINCS.py verify [-m FILE|--message FILE] [-s FILE|--signature FILE] [--public-key FILE]
    SPHINCS.py (-h|--help)

Options:
    -s FILE, --signature FILE    Specify a signature file.
    -m FILE, --message FILE      Specify a message file.
             --secret-key FILE   Specify a secret-key file.
             --public-key FILE   Specify a public-key file.
```

#### Unit tests

This project includes several extensive unit tests. They are comptabile with `nose2`, so calling `nose2` from the project root directory is the easiest way to execute these.

### Relation to reference implementation

This implementation was constructed based on the descriptions in the paper that introduces SPHINCS [1], rather than using the provided reference implementation. This leads to a few noteworthy design choices.

- In the paper, the addresses are specifies as 3-tuples of integers. In order to use these for seed generation, they need to be converted to byte sequences. The convention chosen in the reference implementation (i.e. leaf-first concatenation and litte-endian conversion) is adhered to here as well.
- The paper specifies that, with _R = (R<sub>1</sub>, R<sub>2</sub>)_ ∈ {0, 1}<sup>n</sup> x {0, 1}<sup>n</sup>, the leaf index i is defined as _i =_ Chop(_R<sub>2</sub>, h_). The reference implementation uses the rightmost chunk of 64 bits to compute _i_, however, and starts selecting bits for R<sub>1</sub> from the third chunk. This implementation explicitly uses the bits from _R_ from start to end instead, effectively interpreting _R = F(M, SK<sub>2</sub>)_ as big-endian. See [`SPHINCS.py:110`](https://github.com/joostrijneveld/SPHINCS-py/blob/master/SPHINCS.py#L110) and onwards. In order to make the C code behave identically, one needs to explicitly use a big-endian byte order to initialise _i_ as well.
- When computing the digest, the reference implementation currently includes the public key, i.e. _D = H(R<sub>1</sub> | Q | PK1 | M)_. This implementation uses _D = H(R<sub>1</sub> | M)_, as is specified in the paper.

All of the above implies that the test vectors for WOTS+ and HORST (and ChaCha and BLAKE) provided in the `tests/` directory match the results from the reference implementation, but the example signature for SPHINCS-256 does not. To get these to match, one needs to account for the above differences.

- - -

[1] Daniel J. Bernstein, Daira Hopwood, Andreas Hülsing, Tanja Lange, Ruben Niederhagen, Louiza Papachristodoulou, Peter Schwabe, and Zooko Wilcox- O’Hearn. SPHINCS: practical stateless hash-based signatures. In Marc Fischlin and Elisabeth Oswald, editors, _Advances in Cryptology – EUROCRYPT 2015_, volume 9056 of _LNCS_, pages 368–397. Springer, 2015. Document ID: 5c2820cfddf4e259cc7ea1eda384c9f9, http://cryptojedi.org/papers/#sphincs.
