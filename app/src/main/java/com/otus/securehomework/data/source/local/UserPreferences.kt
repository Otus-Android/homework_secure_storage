package com.otus.securehomework.data.source.local

import com.otus.securehomework.security.crypto.CIPHERTEXT_WRAPPER_ACCESS_TOKEN
import com.otus.securehomework.security.crypto.CIPHERTEXT_WRAPPER_REFRESH_TOKEN
import com.otus.securehomework.security.crypto.CryptographyManager
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import javax.inject.Inject

class UserPreferences
@Inject constructor(
    private val cryptographyManager: CryptographyManager,
) {

    val accessToken: Flow<CharSequence?>
        get() = flowOf(cryptographyManager.getEncryptionOutputFromSharedPrefs(CIPHERTEXT_WRAPPER_ACCESS_TOKEN)?.let {
            val secretKey = cryptographyManager.generateAesKey()
            cryptographyManager.decrypt(secretKey, it.iv, it.aad, it.tag, it.ciphertext).decodeToString()
        })

    val refreshToken: Flow<CharSequence?>
        get() = flowOf(cryptographyManager.getEncryptionOutputFromSharedPrefs(CIPHERTEXT_WRAPPER_REFRESH_TOKEN)?.let {
            val secretKey = cryptographyManager.generateAesKey()
            cryptographyManager.decrypt(secretKey, it.iv, it.aad, it.tag, it.ciphertext).decodeToString()
        })

    suspend fun saveAccessTokens(accessToken: CharSequence?, refreshToken: CharSequence?) {
        val secretKey = cryptographyManager.generateAesKey()
        accessToken?.let {
            val output = cryptographyManager.encrypt(secretKey, it.toString().toByteArray())
            cryptographyManager.persistEncryptionOutputToSharedPrefs(output, CIPHERTEXT_WRAPPER_ACCESS_TOKEN)
        }
        refreshToken?.let {
            val output = cryptographyManager.encrypt(secretKey, it.toString().toByteArray())
            cryptographyManager.persistEncryptionOutputToSharedPrefs(output, CIPHERTEXT_WRAPPER_REFRESH_TOKEN)
        }
    }

    suspend fun clear() {
        cryptographyManager.clearCiphertextWrapperSharedPrefs()
    }
}