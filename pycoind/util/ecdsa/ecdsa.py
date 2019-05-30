#! /usr/bin/env python

"""
Implementation of Elliptic-Curve Digital Signatures.

Classes and methods for elliptic-curve signatures:
private keys, public keys, signatures,
NIST prime-modulus curves with modulus lengths of
192, 224, 256, 384, and 521 bits.

Example:

  # (In real-life applications, you would probably want to
  # protect against defects in SystemRandom.)
  from random import SystemRandom
  randrange = SystemRandom().randrange

  # Generate a public/private key pair using the NIST Curve P-192:

  g = generator_192
  n = g.order()
  secret = randrange( 1, n )
  pubkey = Public_key( g, g * secret )
  privkey = Private_key( pubkey, secret )

  # Signing a hash value:

  hash = randrange( 1, n )
  signature = privkey.sign( hash, randrange( 1, n ) )

  # Verifying a signature for a hash value:

  if pubkey.verifies( hash, signature ):
    print_("Demo verification succeeded.")
  else:
    print_("*** Demo verification failed.")

  # Verification fails if the hash value is modified:

  if pubkey.verifies( hash-1, signature ):
    print_("**** Demo verification failed to reject tampered hash.")
  else:
    print_("Demo verification correctly rejected tampered hash.")

Version of 2009.05.16.

Revision history:
      2005.12.31 - Initial version.
      2008.11.25 - Substantial revisions introducing new classes.
      2009.05.16 - Warn against using random.randrange in real applications.
      2009.05.17 - Use random.SystemRandom by default.

Written in 2005 by Peter Pearson and placed in the public domain.
"""

from .six import int2byte, b, print_
from . import ellipticcurve
from . import numbertheory
import random


class Signature(object):
    """ECDSA signature.
  """

    def __init__(self, r, s):
        self.r = r
        self.s = s


class Public_key(object):
    """Public key for ECDSA.
  """

    def __init__(self, generator, point):
        """generator is the Point that generates the group,
    point is the Point that defines the public key.
    """

        self.curve = generator.curve()
        self.generator = generator
        self.point = point
        n = generator.order()
        if not n:
            raise RuntimeError("Generator point must have order.")
        if not n * point == ellipticcurve.INFINITY:
            raise RuntimeError("Generator point order is bad.")
        if point.x() < 0 or n <= point.x() or point.y() < 0 or n <= point.y():
            raise RuntimeError("Generator point has x or y out of range.")

    def verifies(self, hash, signature):
        """Verify that signature is a valid signature of hash.
    Return True if the signature is valid.
    """

        # From X9.62 J.3.1.

        G = self.generator
        n = G.order()
        r = signature.r
        s = signature.s
        if r < 1 or r > n - 1:
            return False
        if s < 1 or s > n - 1:
            return False
        c = numbertheory.inverse_mod(s, n)
        u1 = (hash * c) % n
        u2 = (r * c) % n
        xy = u1 * G + u2 * self.point
        v = xy.x() % n
        return v == r


class Private_key(object):
    """Private key for ECDSA.
  """

    def __init__(self, public_key, secret_multiplier):
        """public_key is of class Public_key;
    secret_multiplier is a large integer.
    """

        self.public_key = public_key
        self.secret_multiplier = secret_multiplier

    def sign(self, hash, random_k):
        """Return a signature for the provided hash, using the provided
    random nonce.  It is absolutely vital that random_k be an unpredictable
    number in the range [1, self.public_key.point.order()-1].  If
    an attacker can guess random_k, he can compute our private key from a
    single signature.  Also, if an attacker knows a few high-order
    bits (or a few low-order bits) of random_k, he can compute our private
    key from many signatures.  The generation of nonces with adequate
    cryptographic strength is very difficult and far beyond the scope
    of this comment.

    May raise RuntimeError, in which case retrying with a new
    random value k is in order.
    """

        G = self.public_key.generator
        n = G.order()
        k = random_k % n
        p1 = k * G
        r = p1.x()
        if r == 0:
            raise RuntimeError("amazingly unlucky random number r")
        s = (
            numbertheory.inverse_mod(k, n) * (hash + (self.secret_multiplier * r) % n)
        ) % n
        if s == 0:
            raise RuntimeError("amazingly unlucky random number s")
        return Signature(r, s)


def int_to_string(x):
    """Convert integer x into a string of bytes, as per X9.62."""
    assert x >= 0
    if x == 0:
        return b("\0")
    result = []
    while x:
        ordinal = x & 0xFF
        result.append(int2byte(ordinal))
        x >>= 8

    result.reverse()
    return b("").join(result)


def string_to_int(s):
    """Convert a string of bytes into an integer, as per X9.62."""
    result = 0
    for c in s:
        if not isinstance(c, int):
            c = ord(c)
        result = 256 * result + c
    return result


def digest_integer(m):
    """Convert an integer into a string of bytes, compute
     its SHA-1 hash, and convert the result to an integer."""
    #
    # I don't expect this function to be used much. I wrote
    # it in order to be able to duplicate the examples
    # in ECDSAVS.
    #
    from hashlib import sha1

    return string_to_int(sha1(int_to_string(m)).digest())


def point_is_valid(generator, x, y):
    """Is (x,y) a valid public key based on the specified generator?"""

    # These are the tests specified in X9.62.

    n = generator.order()
    curve = generator.curve()
    if x < 0 or n <= x or y < 0 or n <= y:
        return False
    if not curve.contains_point(x, y):
        return False
    if not n * ellipticcurve.Point(curve, x, y) == ellipticcurve.INFINITY:
        return False
    return True


# NIST Curve P-192:
_p = 6277101735386680763835789423207666416083908700390324961279
_r = 6277101735386680763835789423176059013767194773182842284081
# s = 0x3045ae6fc8422f64ed579528d38120eae12196d5L
# c = 0x3099d2bbbfcb2538542dcd5fb078b6ef5f3d6fe2c745de65L
_b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1
_Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
_Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811

curve_192 = ellipticcurve.CurveFp(_p, -3, _b)
generator_192 = ellipticcurve.Point(curve_192, _Gx, _Gy, _r)


# NIST Curve P-224:
_p = 26959946667150639794667015087019630673557916260026308143510066298881
_r = 26959946667150639794667015087019625940457807714424391721682722368061
# s = 0xbd71344799d5c7fcdc45b59fa3b9ab8f6a948bc5L
# c = 0x5b056c7e11dd68f40469ee7f3c7a7d74f7d121116506d031218291fbL
_b = 0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4
_Gx = 0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21
_Gy = 0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34

curve_224 = ellipticcurve.CurveFp(_p, -3, _b)
generator_224 = ellipticcurve.Point(curve_224, _Gx, _Gy, _r)

# NIST Curve P-256:
_p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
_r = 115792089210356248762697446949407573529996955224135760342422259061068512044369
# s = 0xc49d360886e704936a6678e1139d26b7819f7e90L
# c = 0x7efba1662985be9403cb055c75d4f7e0ce8d84a9c5114abcaf3177680104fa0dL
_b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

curve_256 = ellipticcurve.CurveFp(_p, -3, _b)
generator_256 = ellipticcurve.Point(curve_256, _Gx, _Gy, _r)

# NIST Curve P-384:
_p = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319
_r = 39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643
# s = 0xa335926aa319a27a1d00896a6773a4827acdac73L
# c = 0x79d1e655f868f02fff48dcdee14151ddb80643c1406d0ca10dfe6fc52009540a495e8042ea5f744f6e184667cc722483L
_b = 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
_Gx = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
_Gy = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F

curve_384 = ellipticcurve.CurveFp(_p, -3, _b)
generator_384 = ellipticcurve.Point(curve_384, _Gx, _Gy, _r)

# NIST Curve P-521:
_p = 6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151
_r = 6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449
# s = 0xd09e8800291cb85396cc6717393284aaa0da64baL
# c = 0x0b48bfa5f420a34949539d2bdfc264eeeeb077688e44fbf0ad8f6d0edb37bd6b533281000518e19f1b9ffbe0fe9ed8a3c2200b8f875e523868c70c1e5bf55bad637L
_b = 0x051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00
_Gx = 0xC6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66
_Gy = 0x11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650

curve_521 = ellipticcurve.CurveFp(_p, -3, _b)
generator_521 = ellipticcurve.Point(curve_521, _Gx, _Gy, _r)

# Certicom secp256-k1
_a = 0x0000000000000000000000000000000000000000000000000000000000000000
_b = 0x0000000000000000000000000000000000000000000000000000000000000007
_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

curve_secp256k1 = ellipticcurve.CurveFp(_p, _a, _b)
generator_secp256k1 = ellipticcurve.Point(curve_secp256k1, _Gx, _Gy, _r)


def __main__():
    class TestFailure(Exception):
        pass

    def test_point_validity(generator, x, y, expected):
        """generator defines the curve; is (x,y) a point on
       this curve? "expected" is True if the right answer is Yes."""
        if point_is_valid(generator, x, y) == expected:
            print_("Point validity tested as expected.")
        else:
            raise TestFailure("*** Point validity test gave wrong result.")

    def test_signature_validity(Msg, Qx, Qy, R, S, expected):
        """Msg = message, Qx and Qy represent the base point on
       elliptic curve c192, R and S are the signature, and
       "expected" is True iff the signature is expected to be valid."""
        pubk = Public_key(generator_192, ellipticcurve.Point(curve_192, Qx, Qy))
        got = pubk.verifies(digest_integer(Msg), Signature(R, S))
        if got == expected:
            print_(
                "Signature tested as expected: got %s, expected %s." % (got, expected)
            )
        else:
            raise TestFailure(
                "*** Signature test failed: got %s, expected %s." % (got, expected)
            )

    print_("NIST Curve P-192:")

    p192 = generator_192

    # From X9.62:

    d = 651056770906015076056810763456358567190100156695615665659
    Q = d * p192
    if Q.x() != 0x62B12D60690CDCF330BABAB6E69763B471F994DD702D16A5:
        raise TestFailure("*** p192 * d came out wrong.")
    else:
        print_("p192 * d came out right.")

    k = 6140507067065001063065065565667405560006161556565665656654
    R = k * p192
    if (
        R.x() != 0x885052380FF147B734C330C43D39B2C4A89F29B0F749FEAD
        or R.y() != 0x9CF9FA1CBEFEFB917747A3BB29C072B9289C2547884FD835
    ):
        raise TestFailure("*** k * p192 came out wrong.")
    else:
        print_("k * p192 came out right.")

    u1 = 2563697409189434185194736134579731015366492496392189760599
    u2 = 6266643813348617967186477710235785849136406323338782220568
    temp = u1 * p192 + u2 * Q
    if (
        temp.x() != 0x885052380FF147B734C330C43D39B2C4A89F29B0F749FEAD
        or temp.y() != 0x9CF9FA1CBEFEFB917747A3BB29C072B9289C2547884FD835
    ):
        raise TestFailure("*** u1 * p192 + u2 * Q came out wrong.")
    else:
        print_("u1 * p192 + u2 * Q came out right.")

    e = 968236873715988614170569073515315707566766479517
    pubk = Public_key(generator_192, generator_192 * d)
    privk = Private_key(pubk, d)
    sig = privk.sign(e, k)
    r, s = sig.r, sig.s
    if (
        r != 3342403536405981729393488334694600415596881826869351677613
        or s != 5735822328888155254683894997897571951568553642892029982342
    ):
        raise TestFailure("*** r or s came out wrong.")
    else:
        print_("r and s came out right.")

    valid = pubk.verifies(e, sig)
    if valid:
        print_("Signature verified OK.")
    else:
        raise TestFailure("*** Signature failed verification.")

    valid = pubk.verifies(e - 1, sig)
    if not valid:
        print_("Forgery was correctly rejected.")
    else:
        raise TestFailure("*** Forgery was erroneously accepted.")

    print_("Testing point validity, as per ECDSAVS.pdf B.2.2:")

    test_point_validity(
        p192,
        0xCD6D0F029A023E9AACA429615B8F577ABEE685D8257CC83A,
        0x00019C410987680E9FB6C0B6ECC01D9A2647C8BAE27721BACDFC,
        False,
    )

    test_point_validity(
        p192,
        0x00017F2FCE203639E9EAF9FB50B81FC32776B30E3B02AF16C73B,
        0x95DA95C5E72DD48E229D4748D4EEE658A9A54111B23B2ADB,
        False,
    )

    test_point_validity(
        p192,
        0x4F77F8BC7FCCBADD5760F4938746D5F253EE2168C1CF2792,
        0x000147156FF824D131629739817EDB197717C41AAB5C2A70F0F6,
        False,
    )

    test_point_validity(
        p192,
        0xC58D61F88D905293BCD4CD0080BCB1B7F811F2FFA41979F6,
        0x8804DC7A7C4C7F8B5D437F5156F3312CA7D6DE8A0E11867F,
        True,
    )

    test_point_validity(
        p192,
        0xCDF56C1AA3D8AFC53C521ADF3FFB96734A6A630A4A5B5A70,
        0x97C1C44A5FB229007B5EC5D25F7413D170068FFD023CAA4E,
        True,
    )

    test_point_validity(
        p192,
        0x89009C0DC361C81E99280C8E91DF578DF88CDF4B0CDEDCED,
        0x27BE44A529B7513E727251F128B34262A0FD4D8EC82377B9,
        True,
    )

    test_point_validity(
        p192,
        0x6A223D00BD22C52833409A163E057E5B5DA1DEF2A197DD15,
        0x7B482604199367F1F303F9EF627F922F97023E90EAE08ABF,
        True,
    )

    test_point_validity(
        p192,
        0x6DCCBDE75C0948C98DAB32EA0BC59FE125CF0FB1A3798EDA,
        0x0001171A3E0FA60CF3096F4E116B556198DE430E1FBD330C8835,
        False,
    )

    test_point_validity(
        p192,
        0xD266B39E1F491FC4ACBBBC7D098430931CFA66D55015AF12,
        0x193782EB909E391A3148B7764E6B234AA94E48D30A16DBB2,
        False,
    )

    test_point_validity(
        p192,
        0x9D6DDBCD439BAA0C6B80A654091680E462A7D1D3F1FFEB43,
        0x6AD8EFC4D133CCF167C44EB4691C80ABFFB9F82B932B8CAA,
        False,
    )

    test_point_validity(
        p192,
        0x146479D944E6BDA87E5B35818AA666A4C998A71F4E95EDBC,
        0xA86D6FE62BC8FBD88139693F842635F687F132255858E7F6,
        False,
    )

    test_point_validity(
        p192,
        0xE594D4A598046F3598243F50FD2C7BD7D380EDB055802253,
        0x509014C0C4D6B536E3CA750EC09066AF39B4C8616A53A923,
        False,
    )

    print_("Trying signature-verification tests from ECDSAVS.pdf B.2.4:")
    print_("P-192:")
    Msg = 0x84CE72AA8699DF436059F052AC51B6398D2511E49631BCB7E71F89C499B9EE425DFBC13A5F6D408471B054F2655617CBBAF7937B7C80CD8865CF02C8487D30D2B0FBD8B2C4E102E16D828374BBC47B93852F212D5043C3EA720F086178FF798CC4F63F787B9C2E419EFA033E7644EA7936F54462DC21A6C4580725F7F0E7D158
    Qx = 0xD9DBFB332AA8E5FF091E8CE535857C37C73F6250FFB2E7AC
    Qy = 0x282102E364FEDED3AD15DDF968F88D8321AA268DD483EBC4
    R = 0x64DCA58A20787C488D11D6DD96313F1B766F2D8EFE122916
    S = 0x1ECBA28141E84AB4ECAD92F56720E2CC83EB3D22DEC72479
    test_signature_validity(Msg, Qx, Qy, R, S, True)

    Msg = 0x94BB5BACD5F8EA765810024DB87F4224AD71362A3C28284B2B9F39FAB86DB12E8BEB94AAE899768229BE8FDB6C4F12F28912BB604703A79CCFF769C1607F5A91450F30BA0460D359D9126CBD6296BE6D9C4BB96C0EE74CBB44197C207F6DB326AB6F5A659113A9034E54BE7B041CED9DCF6458D7FB9CBFB2744D999F7DFD63F4
    Qx = 0x3E53EF8D3112AF3285C0E74842090712CD324832D4277AE7
    Qy = 0xCC75F8952D30AEC2CBB719FC6AA9934590B5D0FF5A83ADB7
    R = 0x8285261607283BA18F335026130BAB31840DCFD9C3E555AF
    S = 0x356D89E1B04541AFC9704A45E9C535CE4A50929E33D7E06C
    test_signature_validity(Msg, Qx, Qy, R, S, True)

    Msg = 0xF6227A8EEB34AFED1621DCC89A91D72EA212CB2F476839D9B4243C66877911B37B4AD6F4448792A7BBBA76C63BDD63414B6FACAB7DC71C3396A73BD7EE14CDD41A659C61C99B779CECF07BC51AB391AA3252386242B9853EA7DA67FD768D303F1B9B513D401565B6F1EB722DFDB96B519FE4F9BD5DE67AE131E64B40E78C42DD
    Qx = 0x16335DBE95F8E8254A4E04575D736BEFB258B8657F773CB7
    Qy = 0x421B13379C59BC9DCE38A1099CA79BBD06D647C7F6242336
    R = 0x4141BD5D64EA36C5B0BD21EF28C02DA216ED9D04522B1E91
    S = 0x159A6AA852BCC579E821B7BB0994C0861FB08280C38DAA09
    test_signature_validity(Msg, Qx, Qy, R, S, False)

    Msg = 0x16B5F93AFD0D02246F662761ED8E0DD9504681ED02A253006EB36736B563097BA39F81C8E1BCE7A16C1339E345EFABBC6BAA3EFB0612948AE51103382A8EE8BC448E3EF71E9F6F7A9676694831D7F5DD0DB5446F179BCB737D4A526367A447BFE2C857521C7F40B6D7D7E01A180D92431FB0BBD29C04A0C420A57B3ED26CCD8A
    Qx = 0xFD14CDF1607F5EFB7B1793037B15BDF4BAA6F7C16341AB0B
    Qy = 0x83FA0795CC6C4795B9016DAC928FD6BAC32F3229A96312C4
    R = 0x8DFDB832951E0167C5D762A473C0416C5C15BC1195667DC1
    S = 0x1720288A2DC13FA1EC78F763F8FE2FF7354A7E6FDDE44520
    test_signature_validity(Msg, Qx, Qy, R, S, False)

    Msg = 0x08A2024B61B79D260E3BB43EF15659AEC89E5B560199BC82CF7C65C77D39192E03B9A895D766655105EDD9188242B91FBDE4167F7862D4DDD61E5D4AB55196683D4F13CEB90D87AEA6E07EB50A874E33086C4A7CB0273A8E1C4408F4B846BCEAE1EBAAC1B2B2EA851A9B09DE322EFE34CEBE601653EFD6DDC876CE8C2F2072FB
    Qx = 0x674F941DC1A1F8B763C9334D726172D527B90CA324DB8828
    Qy = 0x65ADFA32E8B236CB33A3E84CF59BFB9417AE7E8EDE57A7FF
    R = 0x9508B9FDD7DAF0D8126F9E2BC5A35E4C6D800B5B804D7796
    S = 0x36F2BF6B21B987C77B53BB801B3435A577E3D493744BFAB0
    test_signature_validity(Msg, Qx, Qy, R, S, False)

    Msg = 0x1843ABA74B0789D4AC6B0B8923848023A644A7B70AFA23B1191829BBE4397CE15B629BF21A8838298653ED0C19222B95FA4F7390D1B4C844D96E645537E0AAE98AFB5C0AC3BD0E4C37F8DAAFF25556C64E98C319C52687C904C4DE7240A1CC55CD9756B7EDAEF184E6E23B385726E9FFCBA8001B8F574987C1A3FEDAAA83CA6D
    Qx = 0x10ECCA1AAD7220B56A62008B35170BFD5E35885C4014A19F
    Qy = 0x04EB61984C6C12ADE3BC47F3C629ECE7AA0A033B9948D686
    R = 0x82BFA4E82C0DFE9274169B86694E76CE993FD83B5C60F325
    S = 0xA97685676C59A65DBDE002FE9D613431FB183E8006D05633
    test_signature_validity(Msg, Qx, Qy, R, S, False)

    Msg = 0x5A478F4084DDD1A7FEA038AA9732A822106385797D02311AEEF4D0264F824F698DF7A48CFB6B578CF3DA416BC0799425BB491BE5B5ECC37995B85B03420A98F2C4DC5C31A69A379E9E322FBE706BBCAF0F77175E05CBB4FA162E0DA82010A278461E3E974D137BC746D1880D6EB02AA95216014B37480D84B87F717BB13F76E1
    Qx = 0x6636653CB5B894CA65C448277B29DA3AD101C4C2300F7C04
    Qy = 0xFDF1CBB3FC3FD6A4F890B59E554544175FA77DBDBEB656C1
    R = 0xEAC2DDECDDFB79931A9C3D49C08DE0645C783A24CB365E1C
    S = 0x3549FEE3CFA7E5F93BC47D92D8BA100E881A2A93C22F8D50
    test_signature_validity(Msg, Qx, Qy, R, S, False)

    Msg = 0xC598774259A058FA65212AC57EAA4F52240E629EF4C310722088292D1D4AF6C39B49CE06BA77E4247B20637174D0BD67C9723FEB57B5EAD232B47EA452D5D7A089F17C00B8B6767E434A5E16C231BA0EFA718A340BF41D67EA2D295812FF1B9277DAACB8BC27B50EA5E6443BCF95EF4E9F5468FE78485236313D53D1C68F6BA2
    Qx = 0xA82BD718D01D354001148CD5F69B9EBF38FF6F21898F8AAA
    Qy = 0xE67CEEDE07FC2EBFAFD62462A51E4B6C6B3D5B537B7CAF3E
    R = 0x4D292486C620C3DE20856E57D3BB72FCDE4A73AD26376955
    S = 0xA85289591A6081D5728825520E62FF1C64F94235C04C7F95
    test_signature_validity(Msg, Qx, Qy, R, S, False)

    Msg = 0xCA98ED9DB081A07B7557F24CED6C7B9891269A95D2026747ADD9E9EB80638A961CF9C71A1B9F2C29744180BD4C3D3DB60F2243C5C0B7CC8A8D40A3F9A7FC910250F2187136EE6413FFC67F1A25E1C4C204FA9635312252AC0E0481D89B6D53808F0C496BA87631803F6C572C1F61FA049737FDACCE4ADFF757AFED4F05BEB658
    Qx = 0x7D3B016B57758B160C4FCA73D48DF07AE3B6B30225126C2F
    Qy = 0x4AF3790D9775742BDE46F8DA876711BE1B65244B2B39E7EC
    R = 0x95F778F5F656511A5AB49A5D69DDD0929563C29CBC3A9E62
    S = 0x75C87FC358C251B4C83D2DD979FAAD496B539F9F2EE7A289
    test_signature_validity(Msg, Qx, Qy, R, S, False)

    Msg = 0x31DD9A54C8338BEA06B87ECA813D555AD1850FAC9742EF0BBE40DAD400E10288ACC9C11EA7DAC79EB16378EBEA9490E09536099F1B993E2653CD50240014C90A9C987F64545ABC6A536B9BD2435EB5E911FDFDE2F13BE96EA36AD38DF4AE9EA387B29CCED599AF777338AF2794820C9CCE43B51D2112380A35802AB7E396C97A
    Qx = 0x9362F28C4EF96453D8A2F849F21E881CD7566887DA8BEB4A
    Qy = 0xE64D26D8D74C48A024AE85D982EE74CD16046F4EE5333905
    R = 0xF3923476A296C88287E8DE914B0B324AD5A963319A4FE73B
    S = 0xF0BAEED7624ED00D15244D8BA2AEDE085517DBDEC8AC65F5
    test_signature_validity(Msg, Qx, Qy, R, S, True)

    Msg = 0xB2B94E4432267C92F9FDB9DC6040C95FFA477652761290D3C7DE312283F6450D89CC4AABE748554DFB6056B2D8E99C7AEAAD9CDDDEBDEE9DBC099839562D9064E68E7BB5F3A6BBA0749CA9A538181FC785553A4000785D73CC207922F63E8CE1112768CB1DE7B673AED83A1E4A74592F1268D8E2A4E9E63D414B5D442BD0456D
    Qx = 0xCC6FC032A846AAAC25533EB033522824F94E670FA997ECEF
    Qy = 0xE25463EF77A029ECCDA8B294FD63DD694E38D223D30862F1
    R = 0x066B1D07F3A40E679B620EDA7F550842A35C18B80C5EBE06
    S = 0xA0B0FB201E8F2DF65E2C4508EF303BDC90D934016F16B2DC
    test_signature_validity(Msg, Qx, Qy, R, S, False)

    Msg = 0x4366FCADF10D30D086911DE30143DA6F579527036937007B337F7282460EAE5678B15CCCDA853193EA5FC4BC0A6B9D7A31128F27E1214988592827520B214EED5052F7775B750B0C6B15F145453BA3FEE24A085D65287E10509EB5D5F602C440341376B95C24E5C4727D4B859BFE1483D20538ACDD92C7997FA9C614F0F839D7
    Qx = 0x955C908FE900A996F7E2089BEE2F6376830F76A19135E753
    Qy = 0xBA0C42A91D3847DE4A592A46DC3FDAF45A7CC709B90DE520
    R = 0x1F58AD77FC04C782815A1405B0925E72095D906CBF52A668
    S = 0xF2E93758B3AF75EDF784F05A6761C9B9A6043C66B845B599
    test_signature_validity(Msg, Qx, Qy, R, S, False)

    Msg = 0x543F8AF57D750E33AA8565E0CAE92BFA7A1FF78833093421C2942CADF9986670A5FF3244C02A8225E790FBF30EA84C74720ABF99CFD10D02D34377C3D3B41269BEA763384F372BB786B5846F58932DEFA68023136CD571863B304886E95E52E7877F445B9364B3F06F3C28DA12707673FECB4B8071DE06B6E0A3C87DA160CEF3
    Qx = 0x31F7FA05576D78A949B24812D4383107A9A45BB5FCCDD835
    Qy = 0x8DC0EB65994A90F02B5E19BD18B32D61150746C09107E76B
    R = 0xBE26D59E4E883DDE7C286614A767B31E49AD88789D3A78FF
    S = 0x8762CA831C1CE42DF77893C9B03119428E7A9B819B619068
    test_signature_validity(Msg, Qx, Qy, R, S, False)

    Msg = 0xD2E8454143CE281E609A9D748014DCEBB9D0BC53ADB02443A6AAC2FFE6CB009F387C346ECB051791404F79E902EE333AD65E5C8CB38DC0D1D39A8DC90ADD5023572720E5B94B190D43DD0D7873397504C0C7AEF2727E628EB6A74411F2E400C65670716CB4A815DC91CBBFEB7CFE8C929E93184C938AF2C078584DA045E8F8D1
    Qx = 0x66AA8EDBBDB5CF8E28CEB51B5BDA891CAE2DF84819FE25C0
    Qy = 0x0C6BC2F69030A7CE58D4A00E3B3349844784A13B8936F8DA
    R = 0xA4661E69B1734F4A71B788410A464B71E7FFE42334484F23
    S = 0x738421CF5E049159D69C57A915143E226CAC8355E149AFE9
    test_signature_validity(Msg, Qx, Qy, R, S, False)

    Msg = 0x6660717144040F3E2F95A4E25B08A7079C702A8B29BABAD5A19A87654BC5C5AFA261512A11B998A4FB36B5D8FE8BD942792FF0324B108120DE86D63F65855E5461184FC96A0A8FFD2CE6D5DFB0230CBBDD98F8543E361B3205F5DA3D500FDC8BAC6DB377D75EBEF3CB8F4D1FF738071AD0938917889250B41DD1D98896CA06FB
    Qx = 0xBCFACF45139B6F5F690A4C35A5FFFA498794136A2353FC77
    Qy = 0x6F4A6C906316A6AFC6D98FE1F0399D056F128FE0270B0F22
    R = 0x9DB679A3DAFE48F7CCAD122933ACFE9DA0970B71C94C21C1
    S = 0x984C2DB99827576C0A41A5DA41E07D8CC768BC82F18C9DA9
    test_signature_validity(Msg, Qx, Qy, R, S, False)

    print_("Testing the example code:")

    # Building a public/private key pair from the NIST Curve P-192:

    g = generator_192
    n = g.order()

    # (random.SystemRandom is supposed to provide
    # crypto-quality random numbers, but as Debian recently
    # illustrated, a systems programmer can accidentally
    # demolish this security, so in serious applications
    # further precautions are appropriate.)

    randrange = random.SystemRandom().randrange

    secret = randrange(1, n)
    pubkey = Public_key(g, g * secret)
    privkey = Private_key(pubkey, secret)

    # Signing a hash value:

    hash = randrange(1, n)
    signature = privkey.sign(hash, randrange(1, n))

    # Verifying a signature for a hash value:

    if pubkey.verifies(hash, signature):
        print_("Demo verification succeeded.")
    else:
        raise TestFailure("*** Demo verification failed.")

    if pubkey.verifies(hash - 1, signature):
        raise TestFailure("**** Demo verification failed to reject tampered hash.")
    else:
        print_("Demo verification correctly rejected tampered hash.")


if __name__ == "__main__":
    __main__()
