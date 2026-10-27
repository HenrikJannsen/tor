/*
 * A copy of net.freehaven.tor.control.PasswordDigest of jtorctl, the Java library of the Tor control protocol, from
 * https://github.com/bisq-network/jtorctl at commit 30db998d855ff351c6f74783ff386f15304e875a. The Tor build had the
 * whole library as its module jtorctl, but used only this class. Changes: the package, and the hex encoding uses
 * Guava instead of the Bytes class of jtorctl, with the same upper case output.
 *
 * The LICENSE file of jtorctl:
 *
 * The Tor controller demonstration code is distributed under this license:
 *
 * Copyright (c) 2005, Nick Mathewson, Roger Dingledine
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *
 *     * Neither the names of the copyright owners nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package bisq.network.tor.controller;

import com.google.common.io.BaseEncoding;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * A hashed digest of a secret password (used to set control connection
 * security.)
 *
 * For the actual hashing algorithm, see RFC2440's secret-to-key conversion.
 */
public class PasswordDigest {

    private final byte[] secret;
    private final String hashedKey;

    /** Return a new password digest with a random secret and salt. */
    public static PasswordDigest generateDigest() {
        byte[] secret = new byte[20];
        SecureRandom rng = new SecureRandom();
        rng.nextBytes(secret);
        return new PasswordDigest(secret);
    }

    /** Construct a new password digest with a given secret and random salt */
    public PasswordDigest(byte[] secret) {
        this(secret, null);
    }

    /** Construct a new password digest with a given secret and random salt.
     * Note that the 9th byte of the specifier determines the number of hash
     * iterations as in RFC2440.
     */
    public PasswordDigest(byte[] secret, byte[] specifier) {
        this.secret = secret.clone();
        if (specifier == null) {
            specifier = new byte[9];
            SecureRandom rng = new SecureRandom();
            rng.nextBytes(specifier);
            specifier[8] = 96;
        }
        hashedKey = "16:"+encodeBytes(secretToKey(secret, specifier));
    }

    /** Return the secret used to generate this password hash.
     */
    public byte[] getSecret() {
        return secret.clone();
    }

    /** Return the hashed password in the format used by Tor. */
    public String getHashedPassword() {
        return hashedKey;
    }

    /** Parameter used by RFC2440's s2k algorithm. */
    private static final int EXPBIAS = 6;

    /** Implement rfc2440 s2k */
    public static byte[] secretToKey(byte[] secret, byte[] specifier) {
        MessageDigest d;
        try {
            d = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("Can't run without sha-1.");
        }
        int c = (specifier[8])&0xff;
        int count = (16 + (c&15)) << ((c>>4) + EXPBIAS);

        byte[] tmp = new byte[8+secret.length];
        System.arraycopy(specifier, 0, tmp, 0, 8);
        System.arraycopy(secret, 0, tmp, 8, secret.length);
        while (count > 0) {
            if (count >= tmp.length) {
                d.update(tmp);
                count -= tmp.length;
            } else {
                d.update(tmp, 0, count);
                count = 0;
            }
        }
        byte[] key = new byte[20+9];
        System.arraycopy(d.digest(), 0, key, 9, 20);
        System.arraycopy(specifier, 0, key, 0, 9);
        return key;
    }

    /** Return an upper case hexadecimal encoding of a byte array. */
    private static final String encodeBytes(byte[] ba) {
        return BaseEncoding.base16().encode(ba);
    }

}
