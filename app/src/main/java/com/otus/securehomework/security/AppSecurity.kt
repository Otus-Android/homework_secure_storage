package com.otus.securehomework.security

import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.annotation.RequiresApi
import androidx.security.crypto.MasterKey
import dagger.hilt.android.qualifiers.ApplicationContext
import java.math.BigInteger
import java.security.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.security.auth.x500.X500Principal

private const val AES_SPECIFICATION = "AES/GCM/NoPadding"
private const val AES_KEY_ALIAS = "AES_app_security_key"

private const val RSA_KEY_ALIAS = "RSA_app_security_key"
private const val RSA_ALGORITHM = "RSA"
private const val RSA_MODE_LESS_THAN_M = "RSA/ECB/PKCS1Padding"
private const val KEY_LENGTH = 256
private const val ENCRYPTED_KEY_NAME = "RSAEncryptedKeysKeyName"
private const val PROVIDER = "AndroidKeyStore"

class AppSecurity @Inject constructor(
    @ApplicationContext private val context: Context
) {

    private val cipher by lazy {
        Cipher.getInstance(AES_SPECIFICATION)
    }

    private val keyStore by lazy {
        KeyStore.getInstance(PROVIDER).apply {
            load(null)
        }
    }

    private val securePrefs: SecuredPrefs by lazy {
        SecuredPrefs(context, getMasterKey(MasterKey.KeyScheme.AES256_GCM))
    }

    //<editor-fold desc="Public API">
    fun encryptData(keyAlias: String = AES_KEY_ALIAS, text: String): ByteArray {
        cipher.init(Cipher.ENCRYPT_MODE, generateSecretKey(keyAlias))
        return cipher.doFinal(text.toByteArray(charset("UTF-8")))
    }

    fun decryptData(keyAlias: String = AES_KEY_ALIAS, encryptedData: ByteArray): String {
        val secretKey = getSecretKey(keyAlias)
            ?: throw IllegalStateException("Cannot decrypt data, that hasn't been previously encrypted.")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, cipher.iv))
        return cipher.doFinal(encryptedData).toString(charset("UTF-8"))
    }
    //</editor-fold>

    private fun getSecretKey(keyAlias: String): SecretKey? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            keyStore.getKey(keyAlias, null) as? SecretKey
        } else {
            getAesSecretKeyLessThanM()
        }
    }

    private fun generateSecretKey(keyAlias: String): SecretKey {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            keyStore.getKey(keyAlias, null) as? SecretKey ?: generateAesSecretKey()
        } else {
            getAesSecretKeyLessThanM() ?: generateAesSecretKey()
        }
    }

    private fun getAesSecretKeyLessThanM(): SecretKey? {
        val encryptedKeyBase64Encoded = getSecretKeyFromSharedPrefs()
        return encryptedKeyBase64Encoded?.let {
            val encryptedKey = Base64.decode(it, Base64.DEFAULT)
            val key = rsaDecryptKey(encryptedKey)
            SecretKeySpec(key, "AES")
        }
    }

    private fun rsaDecryptKey(encryptedKey: ByteArray?): ByteArray {
        val cipher = Cipher.getInstance(RSA_MODE_LESS_THAN_M)
        cipher.init(Cipher.DECRYPT_MODE, getRsaPrivateKey())
        return cipher.doFinal(encryptedKey)
    }

    private fun getSecretKeyFromSharedPrefs(): String? {
        return securePrefs.get(ENCRYPTED_KEY_NAME)
    }

    private fun generateAesSecretKey(): SecretKey {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            getKeyGenerator().generateKey()
        } else {
            generateAndSaveAesSecretKeyLessThanM()
        }
    }

    private fun generateAndSaveAesSecretKeyLessThanM(): SecretKey {
        val key = ByteArray(16)
        SecureRandom().run {
            nextBytes(key)
        }
        val encrypted = Base64.encodeToString(rsaEncryptKey(key), Base64.DEFAULT)
        securePrefs.set(ENCRYPTED_KEY_NAME, encrypted)
        return SecretKeySpec(key, "AES")
    }

    private fun rsaEncryptKey(secret: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(RSA_MODE_LESS_THAN_M)
        cipher.init(Cipher.ENCRYPT_MODE, getRsaPublicKey())
        return cipher.doFinal(secret)
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun getKeyGenerator() = KeyGenerator.getInstance("AES", PROVIDER).apply {
        init(getKeyGenSpec())
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun getKeyGenSpec(): KeyGenParameterSpec {
        return KeyGenParameterSpec.Builder(
            AES_KEY_ALIAS,
            KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .setUserAuthenticationRequired(true)
            .setRandomizedEncryptionRequired(false)
            .build()
    }

    private fun getRsaPublicKey(): PublicKey {
        return keyStore.getCertificate(RSA_KEY_ALIAS)?.publicKey ?: generateRsaSecretKey().public
    }

    private fun getRsaPrivateKey(): PrivateKey {
        return keyStore.getKey(RSA_KEY_ALIAS, null) as? PrivateKey ?: generateRsaSecretKey().private
    }

    private fun generateRsaSecretKey(): KeyPair {
        val spec = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            KeyGenParameterSpec.Builder(
                RSA_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            ).setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .setUserAuthenticationRequired(true)
                .setRandomizedEncryptionRequired(false)
                .build()
        } else {
            val start: Calendar = Calendar.getInstance()
            val end: Calendar = Calendar.getInstance()
            end.add(Calendar.YEAR, 30)
            KeyPairGeneratorSpec.Builder(context)
                .setAlias(RSA_KEY_ALIAS)
                .setSubject(X500Principal("CN=$RSA_KEY_ALIAS"))
                .setSerialNumber(BigInteger.TEN)
                .setStartDate(start.time)
                .setEndDate(end.time)
                .build()
        }
        return KeyPairGenerator.getInstance(RSA_ALGORITHM, PROVIDER).run {
            initialize(spec)
            generateKeyPair()
        }
    }

    private fun getMasterKey(keyScheme: MasterKey.KeyScheme): MasterKey {
        return createOrGetMasterKey(keyScheme)
    }

    private fun createOrGetMasterKey(keyScheme: MasterKey.KeyScheme): MasterKey {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val spec = KeyGenParameterSpec.Builder(
                MasterKey.DEFAULT_MASTER_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(KEY_LENGTH)
                .build()

            MasterKey.Builder(context)
                .setKeyGenParameterSpec(spec)
                .build()
        } else {
            MasterKey.Builder(context)
                .setKeyScheme(keyScheme)
                .build()
        }
    }
}



























