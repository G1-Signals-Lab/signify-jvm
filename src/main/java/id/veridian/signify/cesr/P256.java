package id.veridian.signify.cesr;

import id.veridian.signify.cesr.args.RawArgs;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

/** KERI secp256r1: compressed SEC1 public key; SHA-256; fixed-width r || s. */
public final class P256 {
    private static final ECParameterSpec CURVE = curve();
    private static final BigInteger P = ((java.security.spec.ECFieldFp) CURVE.getCurve().getField()).getP();
    private P256() {}

    public static String nextSeedCode(String publicKey) {
        return switch (Codex.MatterCodex.fromValue(new Verfer(publicKey).getCode())) {
            case ECDSA_256r1, ECDSA_256r1N -> "Q";
            case Ed25519, Ed25519N -> "A";
            default -> throw new IllegalArgumentException("Unsupported next-key algorithm");
        };
    }

    private static ECParameterSpec curve() {
        try {
            var params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec("secp256r1"));
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException failure) {
            throw new ExceptionInInitializerError(failure);
        }
    }

    public static ECPublicKey publicKey(byte[] compressed) {
        if (compressed == null || compressed.length != 33 || (compressed[0] != 2 && compressed[0] != 3)) {
            throw new IllegalArgumentException("Invalid P256 public key");
        }
        var x = new BigInteger(1, Arrays.copyOfRange(compressed, 1, 33));
        if (x.compareTo(P) >= 0) throw new IllegalArgumentException("Invalid P256 public key");
        var rhs = x.multiply(x).multiply(x).add(CURVE.getCurve().getA().multiply(x))
                .add(CURVE.getCurve().getB()).mod(P);
        var y = rhs.modPow(P.add(BigInteger.ONE).shiftRight(2), P);
        if (!y.multiply(y).mod(P).equals(rhs)) throw new IllegalArgumentException("Invalid P256 public key");
        if (y.testBit(0) != (compressed[0] == 3)) y = P.subtract(y);
        try {
            return (ECPublicKey) KeyFactory.getInstance("EC")
                    .generatePublic(new ECPublicKeySpec(new ECPoint(x, y), CURVE));
        } catch (GeneralSecurityException failure) {
            throw new IllegalArgumentException("Invalid P256 public key", failure);
        }
    }

    public static byte[] compress(ECPublicKey key) {
        if (!key.getParams().getCurve().equals(CURVE.getCurve())
                || !key.getParams().getGenerator().equals(CURVE.getGenerator())
                || !key.getParams().getOrder().equals(CURVE.getOrder())) {
            throw new IllegalArgumentException("P256 key required");
        }
        var encoded = new byte[33];
        encoded[0] = (byte) (key.getW().getAffineY().testBit(0) ? 3 : 2);
        var x = key.getW().getAffineX().toByteArray();
        int start = x.length == 33 && x[0] == 0 ? 1 : 0;
        if (x.length - start > 32) throw new IllegalArgumentException("Invalid P256 public key");
        System.arraycopy(x, start, encoded, 33 - (x.length - start), x.length - start);
        publicKey(encoded);
        return encoded;
    }

    public static boolean verify(byte[] signature, byte[] message, byte[] compressedKey) {
        if (signature == null || signature.length != 64 || message == null) return false;
        try {
            var r = new BigInteger(1, Arrays.copyOfRange(signature, 0, 32));
            var s = new BigInteger(1, Arrays.copyOfRange(signature, 32, 64));
            if (r.signum() == 0 || s.signum() == 0
                    || r.compareTo(CURVE.getOrder()) >= 0 || s.compareTo(CURVE.getOrder()) >= 0) return false;
            var verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
            verifier.initVerify(publicKey(compressedKey));
            verifier.update(message);
            return verifier.verify(signature);
        } catch (GeneralSecurityException | IllegalArgumentException failure) {
            return false;
        }
    }

    /** Encodes an already-produced hardware signature; never reads private-key material. */
    public static String encode(byte[] signature, Verfer verifier, Integer index, Integer ondex) {
        if (signature == null || signature.length != 64
                || !("1AAI".equals(verifier.getCode()) || "1AAJ".equals(verifier.getCode()))) {
            throw new IllegalArgumentException("P256 signature required");
        }
        if (index == null) {
            if (ondex != null) throw new IllegalArgumentException("Unexpected signature index");
            return new Cigar(RawArgs.builder().raw(signature.clone()).code("0I").build(), verifier).getQb64();
        }
        if (index < 0 || index > 4095 || (ondex != null && (ondex < 0 || ondex > 4095))) {
            throw new IllegalArgumentException("Invalid signature index");
        }
        String code = ondex == null ? (index <= 63 ? "F" : "2F")
                : (ondex.equals(index) && index <= 63 ? "E" : "2E");
        return new Siger(RawArgs.builder().raw(signature.clone()).code(code).build(), index, ondex, verifier).getQb64();
    }
}
