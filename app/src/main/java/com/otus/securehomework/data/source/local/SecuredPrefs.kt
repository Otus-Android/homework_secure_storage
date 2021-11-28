package com.otus.securehomework.data.source.local

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import javax.inject.Inject

class SecuredPrefs @Inject constructor(context: Context, masterKey: MasterKey) {

    companion object {
        private const val PREF_NAME = "secured_prefs"
        private const val ACCESS_TOKEN = "secured_access_token"
        private const val REFRESH_TOKEN = "secured_refresh_token"
        private const val BIOMETRIC_ENABLED = "biometrics_enabled_state"
        private const val DEFAULT = ""
    }

    private val prefs = EncryptedSharedPreferences.create(
        context, PREF_NAME, masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    val accessToken: Flow<String>
        get() = flowOf(prefs.getString(ACCESS_TOKEN, DEFAULT) ?: DEFAULT)

    val refreshToken: Flow<String>
        get() = flowOf(prefs.getString(REFRESH_TOKEN, DEFAULT) ?: DEFAULT)

    val isBiometricsEnabled: Flow<Boolean>
        get() = flowOf(prefs.getBoolean(BIOMETRIC_ENABLED, false))

    fun saveAccessTokens(accessToken: String?, refreshToken: String?) {
        prefs.edit().putString(ACCESS_TOKEN, accessToken).apply()
        prefs.edit().putString(REFRESH_TOKEN, refreshToken).apply()
    }

    fun updateBiometricsState(state: Boolean) {
        prefs.edit().putBoolean(BIOMETRIC_ENABLED, state).apply()
    }

    fun clearBiometricsState(){
        prefs.edit().remove(BIOMETRIC_ENABLED).apply()
    }

    fun clear() {
        prefs.edit().remove(ACCESS_TOKEN).apply()
        prefs.edit().remove(REFRESH_TOKEN).apply()
    }
}