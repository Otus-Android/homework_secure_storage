/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package com.otus.securehomework.security.crypto

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import com.google.gson.Gson
import dagger.hilt.android.qualifiers.ApplicationContext
import java.nio.charset.Charset
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.inject.Inject

private const val SHARED_PREFS_FILENAME = "biometric_prefs"
const val CIPHERTEXT_WRAPPER_ACCESS_TOKEN = "ciphertext_wrapper_access_token"
const val CIPHERTEXT_WRAPPER_REFRESH_TOKEN = "ciphertext_wrapper_refresh_token"

private const val KEY_SIZE = 256
private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val ENCRYPTION_BLOCK_MODE = KeyProperties.BLOCK_MODE_GCM
private const val ENCRYPTION_PADDING = KeyProperties.ENCRYPTION_PADDING_NONE
private const val ENCRYPTION_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
private const val KEY_NAME = "MY_KEY_SECURITY"

/**
 * Handles encryption and decryption
 */
interface CryptographyManager {

    fun getInitializedCipherForEncryption(): Cipher

    fun getInitializedCipherForDecryption(initializationVector: ByteArray): Cipher

    /**
     * The Cipher created with [getInitializedCipherForEncryption] is used here
     */
    fun encryptData(plaintext: String): CiphertextWrapper

    /**
     * The Cipher created with [getInitializedCipherForDecryption] is used here
     */
    fun decryptData(ciphertext: ByteArray, cipher: Cipher): String

    fun persistCiphertextWrapperToSharedPrefs(ciphertextWrapper: CiphertextWrapper, ciphertextKey: String)

    fun getCiphertextWrapperFromSharedPrefs(ciphertextKey: String): CiphertextWrapper?

    fun clearCiphertextWrapperSharedPrefs()
}

class CryptographyManagerImpl @Inject constructor(
    @ApplicationContext private val context: Context
) : CryptographyManager {

    @RequiresApi(Build.VERSION_CODES.N)
    override fun getInitializedCipherForEncryption(): Cipher {
        val cipher = getCipher()
        val secretKey = getOrCreateSecretKey()
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipher
    }

    @RequiresApi(Build.VERSION_CODES.N)
    override fun getInitializedCipherForDecryption(
        initializationVector: ByteArray
    ): Cipher {
        val cipher = getCipher()
        val secretKey = getOrCreateSecretKey()
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, initializationVector))
        return cipher
    }

    @RequiresApi(Build.VERSION_CODES.N)
    override fun encryptData(plaintext: String): CiphertextWrapper {
        val cipher = getInitializedCipherForEncryption()
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charset.forName("UTF-8")))
        return CiphertextWrapper(ciphertext, cipher.iv)
    }

    @RequiresApi(Build.VERSION_CODES.N)
    override fun decryptData(ciphertext: ByteArray, cipher: Cipher): String {
        val plaintext = cipher.doFinal(ciphertext)
        return String(plaintext, Charset.forName("UTF-8"))
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun getCipher(): Cipher {
        return Cipher.getInstance("$ENCRYPTION_ALGORITHM/$ENCRYPTION_BLOCK_MODE/$ENCRYPTION_PADDING")
    }

    @RequiresApi(Build.VERSION_CODES.N)
    private fun getOrCreateSecretKey(): SecretKey {
        // If SecretKey was previously created for that keyName, then grab and return it.
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null) // Keystore must be loaded before it can be accessed
        keyStore.getKey(KEY_NAME, null)?.let { return it as SecretKey }

        // if you reach here, then a new SecretKey must be generated for that keyName
        return generateSecretKey(getKeyGenParameterSpec())
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun generateSecretKey(keyGenParameterSpec: KeyGenParameterSpec): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE
        )
        keyGenerator.init(keyGenParameterSpec)
        return keyGenerator.generateKey()
    }

    @RequiresApi(Build.VERSION_CODES.N)
    private fun getKeyGenParameterSpec(): KeyGenParameterSpec {
        val paramsBuilder = KeyGenParameterSpec.Builder(
            KEY_NAME,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
        paramsBuilder.apply {
            setBlockModes(ENCRYPTION_BLOCK_MODE)
            setEncryptionPaddings(ENCRYPTION_PADDING)
            setKeySize(KEY_SIZE)
            setUserAuthenticationRequired(true)
            // Invalidate the keys if the user has registered a new biometric
            // credential, such as a new fingerprint. Can call this method only
            // on Android 7.0 (API level 24) or higher. The variable
            // "invalidatedByBiometricEnrollment" is true by default.
            //.setInvalidatedByBiometricEnrollment(true)
        }
        return paramsBuilder.build()
    }

    override fun persistCiphertextWrapperToSharedPrefs(
        ciphertextWrapper: CiphertextWrapper,
        ciphertextKey: String
    ) {
        val json = Gson().toJson(ciphertextWrapper)
        context.getSharedPreferences(SHARED_PREFS_FILENAME, Context.MODE_PRIVATE)
            .edit()
            .putString(ciphertextKey, json)
            .apply()
    }

    override fun getCiphertextWrapperFromSharedPrefs(ciphertextKey: String): CiphertextWrapper? {
        val json = context.getSharedPreferences(SHARED_PREFS_FILENAME, Context.MODE_PRIVATE)
            .getString(ciphertextKey, null)
        return Gson().fromJson(json, CiphertextWrapper::class.java)
    }

    override fun clearCiphertextWrapperSharedPrefs() {
        context.getSharedPreferences(SHARED_PREFS_FILENAME, Context.MODE_PRIVATE)
            .edit()
            .clear()
            .apply()
    }
}

data class CiphertextWrapper(val ciphertext: ByteArray, val initializationVector: ByteArray)
