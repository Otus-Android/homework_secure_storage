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
        get() = flowOf(cryptographyManager.getCiphertextWrapperFromSharedPrefs(CIPHERTEXT_WRAPPER_ACCESS_TOKEN)?.let {
            cryptographyManager.decryptData(it.ciphertext, cryptographyManager.getInitializedCipherForDecryption(it.initializationVector))
        })

    val refreshToken: Flow<CharSequence?>
        get() = flowOf(cryptographyManager.getCiphertextWrapperFromSharedPrefs(CIPHERTEXT_WRAPPER_REFRESH_TOKEN)?.let {
            cryptographyManager.decryptData(it.ciphertext, cryptographyManager.getInitializedCipherForDecryption(it.initializationVector))
        })

    suspend fun saveAccessTokens(accessToken: CharSequence?, refreshToken: CharSequence?) {
        accessToken?.let {
            // todo сейчас падает на api 30 (android 11) с ошибкой:
            // Caused by: android.security.KeyStoreException: Incompatible padding mode
            // если выбираю другие параметры для Cipher, то еще какая-нибудь ошибка будет
            val encryptedAccessTokenWrapper = cryptographyManager.encryptData(it.toString())
            cryptographyManager.persistCiphertextWrapperToSharedPrefs(
                encryptedAccessTokenWrapper,
                CIPHERTEXT_WRAPPER_ACCESS_TOKEN
            )
        }
        refreshToken?.let {
            val encryptedRefreshTokenWrapper = cryptographyManager.encryptData(it.toString())
            cryptographyManager.persistCiphertextWrapperToSharedPrefs(
                encryptedRefreshTokenWrapper,
                CIPHERTEXT_WRAPPER_REFRESH_TOKEN
            )
        }
    }

    suspend fun clear() {
        cryptographyManager.clearCiphertextWrapperSharedPrefs()
    }
}