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
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.inject.Inject

private const val SHARED_PREFS_FILENAME = "biometric_prefs"
const val CIPHERTEXT_WRAPPER_ACCESS_TOKEN = "ciphertext_wrapper_access_token"
const val CIPHERTEXT_WRAPPER_REFRESH_TOKEN = "ciphertext_wrapper_refresh_token"

const val AAD_LENGTH = 16
const val TAG_LENGTH = 16

/**
 * Handles encryption and decryption
 */
interface CryptographyManager {

    fun getInitializedCipherForDecryption(key: SecretKey, iv: ByteArray, aad: ByteArray): Cipher

    fun clearCiphertextWrapperSharedPrefs()

    fun persistEncryptionOutputToSharedPrefs(
        encryptionOutput: CryptographyManagerImpl.EncryptionOutput,
        ciphertextKey: String
    )

    fun getEncryptionOutputFromSharedPrefs(ciphertextKey: String): CryptographyManagerImpl.EncryptionOutput?

    fun generateAesKey(): SecretKey

    fun encrypt(key: SecretKey, message: ByteArray): CryptographyManagerImpl.EncryptionOutput

    fun decrypt(key: SecretKey, iv: ByteArray, aad: ByteArray, tag: ByteArray, ciphertext: ByteArray): ByteArray
}

class CryptographyManagerImpl @Inject constructor(
    @ApplicationContext private val context: Context
) : CryptographyManager {

    override fun getInitializedCipherForDecryption(key: SecretKey, iv: ByteArray, aad: ByteArray): Cipher {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(TAG_LENGTH * 8, iv)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        cipher.updateAAD(aad)
        return cipher
    }

    override fun persistEncryptionOutputToSharedPrefs(
        encryptionOutput: EncryptionOutput,
        ciphertextKey: String
    ) {
        val json = Gson().toJson(encryptionOutput)
        context.getSharedPreferences(SHARED_PREFS_FILENAME, Context.MODE_PRIVATE)
            .edit()
            .putString(ciphertextKey, json)
            .apply()
    }

    override fun getEncryptionOutputFromSharedPrefs(ciphertextKey: String): EncryptionOutput? {
        val json = context.getSharedPreferences(SHARED_PREFS_FILENAME, Context.MODE_PRIVATE)
            .getString(ciphertextKey, null)
        return Gson().fromJson(json, EncryptionOutput::class.java)
    }

    override fun clearCiphertextWrapperSharedPrefs() {
        context.getSharedPreferences(SHARED_PREFS_FILENAME, Context.MODE_PRIVATE)
            .edit()
            .clear()
            .apply()
    }

    @RequiresApi(Build.VERSION_CODES.M)
    override fun generateAesKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val kgps = KeyGenParameterSpec.Builder("my_aes_key2", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            // Так мы получим разрешение
            .setRandomizedEncryptionRequired(false)
            .build()
        keyGenerator.init(kgps)
        return keyGenerator.generateKey()
    }

    class EncryptionOutput(
        val iv: ByteArray,
        val aad: ByteArray,
        val tag: ByteArray,
        val ciphertext: ByteArray
    )

    override fun encrypt(key: SecretKey, message: ByteArray): EncryptionOutput {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv.copyOf()
        val aad = SecureRandom().generateSeed(AAD_LENGTH)
        cipher.updateAAD(aad)

        val result = cipher.doFinal(message)
        val ciphertext = result.copyOfRange(0, result.size - TAG_LENGTH)
        val tag = result.copyOfRange(result.size - TAG_LENGTH, result.size)
        return EncryptionOutput(iv, aad, tag, ciphertext)
    }

    override fun decrypt(key: SecretKey, iv: ByteArray, aad: ByteArray, tag: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = getInitializedCipherForDecryption(key, iv, aad)
        return cipher.doFinal(ciphertext + tag)

        // todo сейчас такое:
        /**
         * E/AndroidRuntime: FATAL EXCEPTION: main
        Process: com.otus.securehomework, PID: 25471
        javax.crypto.AEADBadTagException
        at android.security.keystore.AndroidKeyStoreCipherSpiBase.engineDoFinal(AndroidKeyStoreCipherSpiBase.java:517)
        at javax.crypto.Cipher.doFinal(Cipher.java:2055)
        at com.otus.securehomework.security.crypto.CryptographyManagerImpl.decrypt(CryptographyManager.kt:248)
        at com.otus.securehomework.data.source.local.UserPreferences.getAccessToken(UserPreferences.kt:19)
        at com.otus.securehomework.data.repository.UserRepository.isUserValid(UserRepository.kt:29)
         */
    }
}

