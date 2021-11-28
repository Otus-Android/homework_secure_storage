package com.otus.securehomework.data.source.local

import android.content.Context
import android.content.pm.PackageManager
import androidx.biometric.BiometricPrompt
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import com.otus.securehomework.data.dto.EncryptedObject
import dagger.hilt.android.qualifiers.ApplicationContext
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.inject.Inject

/**
 * реализация частично подсмотрена у TheChonenOne777
 */
class AuthCipher @Inject constructor(@ApplicationContext private val context: Context) {

    val encryptObject: BiometricPrompt.CryptoObject
        @RequiresApi(Build.VERSION_CODES.P)
        get() = BiometricPrompt.CryptoObject(getCipher(Cipher.ENCRYPT_MODE))

    val decryptObject: BiometricPrompt.CryptoObject
        @RequiresApi(Build.VERSION_CODES.P)
        get() = BiometricPrompt.CryptoObject(getCipher(Cipher.DECRYPT_MODE))

    fun encryptText(plaintext: String, cipher: Cipher): EncryptedObject =
        EncryptedObject(cipher.doFinal(plaintext.toByteArray()), cipher.iv)

    fun decryptText(ciphertext: ByteArray, cipher: Cipher): String =
        String(cipher.doFinal(ciphertext), Charsets.UTF_8)

    @RequiresApi(Build.VERSION_CODES.M)
    private fun provideSecretKey(): SecretKey {
        val keystore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

        keystore.getKey("biometrics", null)?.let { return it as SecretKey }

        val keySpec = KeyGenParameterSpec.Builder(
            "biometrics",
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(256)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setUserAuthenticationRequired(true).apply{
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setUnlockedDeviceRequired(true)
                    setIsStrongBoxBacked(context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE))
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                }
            }.build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
            .apply { init(keySpec) }
            .generateKey()
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun getCipher(mode: Int): Cipher{
        return when(mode) {
            Cipher.ENCRYPT_MODE -> {
               Cipher.getInstance(TRANSFORMATION).apply {
                   init(Cipher.ENCRYPT_MODE, provideSecretKey())
               }
            }
            else -> {
                Cipher.getInstance(TRANSFORMATION).apply {
                    init(Cipher.DECRYPT_MODE, provideSecretKey(), GCMParameterSpec(128, iv))
                }
            }
        }
    }

    companion object {
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        @RequiresApi(Build.VERSION_CODES.M)
        private const val TRANSFORMATION = "${KeyProperties.KEY_ALGORITHM_AES}/" +
                "${KeyProperties.BLOCK_MODE_GCM}/" + KeyProperties.ENCRYPTION_PADDING_NONE
    }
}