package id.veridian.signify.cesr;

import static org.junit.jupiter.api.Assertions.*;
import id.veridian.signify.cesr.args.RawArgs;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class P256Test {
    @Test void verifiesIndependentRfc6979PublicVector() {
        // RFC6979 A.2.5: public point and SHA256 signature only; no private test seed.
        var publicKey = HexFormat.of().parseHex(
                "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");
        var signature = HexFormat.of().parseHex(
                "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
                        + "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8");
        assertTrue(P256.verify(signature, "sample".getBytes(java.nio.charset.StandardCharsets.US_ASCII), publicKey));
        assertFalse(P256.verify(signature, "test".getBytes(java.nio.charset.StandardCharsets.US_ASCII), publicKey));
    }

    // NIST P256 generator, a fixed independently specified public point.
    private static final byte[] GENERATOR = HexFormat.of().parseHex(
            "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");

    @Test void acceptsCanonicalGeneratorAndRejectsMalformedPoints() {
        assertArrayEquals(GENERATOR, P256.compress(P256.publicKey(GENERATOR)));
        assertEquals("Q", P256.nextSeedCode(new Verfer(RawArgs.builder().raw(GENERATOR).code("1AAJ").build()).getQb64()));
        assertEquals("A", P256.nextSeedCode("BGgVB5Aar1pOr70nRpJmRA_RP68HErflNovoEMP7b7mJ"));
        for (byte[] bad : new byte[][] {new byte[32], new byte[34], new byte[33],
                HexFormat.of().parseHex("02ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")}) {
            assertThrows(IllegalArgumentException.class, () -> P256.publicKey(bad));
        }
    }

    @Test void verifiesExactBinaryMessageAndRejectsMutation() throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        var keys = generator.generateKeyPair();
        var message = new byte[] {0, (byte) 0xff, (byte) 0xc3, 0x28, 10};
        var signer = Signature.getInstance("SHA256withECDSAinP1363Format");
        signer.initSign(keys.getPrivate()); signer.update(message); var signature = signer.sign();
        var key = P256.compress((ECPublicKey) keys.getPublic());
        assertTrue(P256.verify(signature, message, key));
        assertFalse(P256.verify(signature, new byte[] {0}, key));
        assertFalse(P256.verify(new byte[64], message, key));
        assertFalse(P256.verify(new byte[63], message, key));
        var verfer = new Verfer(RawArgs.builder().raw(key).code("1AAJ").build());
        assertTrue(verfer.verify(signature, message));
        assertEquals(48, verfer.getQb64().length());
        for (int index : new int[] {0, 63, 64, 4095}) {
            for (Integer ondex : new Integer[] {null, index, 3}) {
                var encoded = P256.encode(signature, verfer, index, ondex);
                var parsed = new Siger(encoded);
                assertArrayEquals(signature, parsed.getRaw());
                assertEquals(index, parsed.getIndex());
                assertEquals(ondex, parsed.getOndex());
            }
        }
        assertThrows(IllegalArgumentException.class, () -> P256.encode(signature, verfer, 4096, 0));
    }
}
