package dev.seagent.mobile

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * The app's device key (docs/SECURITY.md §8) in the Android Keystore: ECDSA P-256, signing only,
 * never exportable, StrongBox when the phone has one. The Rust side
 * (`apps/desktop/src-tauri/src/devkey.rs` → `seagent-devkey`) asks for the public key and for
 * signatures over refresh messages; the private key never leaves the Keystore.
 */
object DeviceKeystore {
    private const val PROVIDER = "AndroidKeyStore"

    private fun store(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    private fun generate(alias: String, strongBox: Boolean) {
        val b = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
        if (strongBox && Build.VERSION.SDK_INT >= 28) b.setIsStrongBoxBacked(true)
        val g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
        g.initialize(b.build())
        g.generateKeyPair()
    }

    /** The key under `alias`, created on first use (StrongBox first, then the TEE / software). */
    private fun ensure(alias: String): KeyStore {
        val ks = store()
        if (!ks.containsAlias(alias)) {
            try { generate(alias, true) } catch (e: Exception) { generate(alias, false) }
        }
        return ks
    }

    /** base64 X.509 SubjectPublicKeyInfo, and whether the key lives in secure hardware. */
    fun publicKey(alias: String): Pair<String, Boolean> {
        val ks = ensure(alias)
        val cert = ks.getCertificate(alias) ?: throw IllegalStateException("no device key")
        val priv = ks.getKey(alias, null) as PrivateKey
        val hardware = try {
            val info = KeyFactory.getInstance(priv.algorithm, PROVIDER).getKeySpec(priv, KeyInfo::class.java)
            if (Build.VERSION.SDK_INT >= 31) info.securityLevel != KeyProperties.SECURITY_LEVEL_SOFTWARE else @Suppress("DEPRECATION") info.isInsideSecureHardware
        } catch (e: Exception) { false }
        return Pair(Base64.encodeToString(cert.publicKey.encoded, Base64.NO_WRAP), hardware)
    }

    /** ECDSA-SHA256 over the message; base64 DER signature. */
    fun sign(alias: String, messageB64: String): String {
        val ks = ensure(alias)
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(ks.getKey(alias, null) as PrivateKey)
        s.update(Base64.decode(messageB64, Base64.DEFAULT))
        return Base64.encodeToString(s.sign(), Base64.NO_WRAP)
    }
}
