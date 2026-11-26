// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
package dev.simplego.provisioning.agent;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.util.Base64;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;

/**
 * One key attestation run, started by sxprov over adb:
 *
 *   am instrument -w -r -e challenge HEX AGENT/CLASS
 *
 * Generates a hardware-backed key with the challenge (StrongBox if available,
 * otherwise TEE), returns the certificate chain in the instrumentation result
 * bundle, and deletes the key. Nothing is written to storage. The agent reads
 * no other app: sxprov checks installed apps from their pulled base.apk.
 */
public final class AttestInstrumentation extends Instrumentation {
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final int MIN_CHALLENGE = 32;

    private Bundle arguments = new Bundle();

    @Override
    public void onCreate(Bundle args) {
        super.onCreate(args);
        if (args != null) {
            arguments = args;
        }
        start();
    }

    @Override
    public void onStart() {
        super.onStart();
        Bundle out = new Bundle();
        int code = Activity.RESULT_CANCELED;
        try {
            byte[] challenge = unhex(arguments.getString("challenge"));
            if (challenge.length < MIN_CHALLENGE) {
                throw new IllegalArgumentException("challenge shorter than " + MIN_CHALLENGE + " bytes");
            }
            attest(challenge, out);
            out.putString("status", "ok");
            code = Activity.RESULT_OK;
        } catch (Throwable t) {
            out.putString("status", "error");
            out.putString("error", oneLine(t));
        }
        finish(code, out);
    }

    private static void attest(byte[] challenge, Bundle out) throws Exception {
        String alias = "sxprov-" + hex(random(16));
        KeyStore ks = KeyStore.getInstance(KEYSTORE);
        ks.load(null);
        try {
            String backing;
            try {
                generate(alias, challenge, true);
                backing = "strongbox";
            } catch (StrongBoxUnavailableException e) {
                generate(alias, challenge, false);
                backing = "tee";
            }
            out.putString("keystore", backing);
            Certificate[] chain = ks.getCertificateChain(alias);
            if (chain == null || chain.length == 0) {
                throw new IllegalStateException("no certificate chain for the attested key");
            }
            out.putString("chain_count", Integer.toString(chain.length));
            for (int i = 0; i < chain.length; i++) {
                out.putString("chain_" + i, Base64.encodeToString(chain[i].getEncoded(), Base64.NO_WRAP));
            }
        } finally {
            if (ks.containsAlias(alias)) {
                ks.deleteEntry(alias);
            }
        }
    }

    private static void generate(String alias, byte[] challenge, boolean strongBox) throws Exception {
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
                .setIsStrongBoxBacked(strongBox)
                .build();
        KeyPairGenerator g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE);
        g.initialize(spec);
        g.generateKeyPair();
    }

    private static byte[] random(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }

    private static byte[] unhex(String s) {
        if (s == null || s.length() % 2 != 0) {
            throw new IllegalArgumentException("challenge missing or not hex");
        }
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int hi = Character.digit(s.charAt(2 * i), 16);
            int lo = Character.digit(s.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("challenge not hex");
            }
            b[i] = (byte) ((hi << 4) | lo);
        }
        return b;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xf, 16)).append(Character.forDigit(x & 0xf, 16));
        }
        return sb.toString();
    }

    /** Bundle values are printed one per line by `am instrument -r`. */
    private static String oneLine(Object o) {
        String s = o instanceof Throwable
                ? o.getClass().getName() + ": " + ((Throwable) o).getMessage()
                : String.valueOf(o);
        return s.replace('\r', ' ').replace('\n', ' ');
    }
}
