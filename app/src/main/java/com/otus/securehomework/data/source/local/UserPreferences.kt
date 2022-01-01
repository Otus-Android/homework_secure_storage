package com.otus.securehomework.data.source.local

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.otus.securehomework.security.AppSecurity
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import javax.inject.Inject

private const val dataStoreFile: String = "securePref"

class UserPreferences
@Inject constructor(
    private val context: Context,
    private val appSecurity: AppSecurity
) {
    private val bytesToStringSeparator = "|"

    private val json = Json { encodeDefaults = true }

    private val Context.dataStore by preferencesDataStore(name = dataStoreFile)

    val accessToken: Flow<String?>
        get() = context.dataStore.data.secureMap { preferences ->
            preferences[ACCESS_TOKEN]
        }

    val refreshToken: Flow<String?>
        get() = context.dataStore.data.secureMap { preferences ->
            preferences[REFRESH_TOKEN]
        }

    suspend fun saveAccessTokensSecurely(accessToken: String?, refreshToken: String?) {
        accessToken?.let { accessTokenStr ->
            context.dataStore.secureEdit(accessTokenStr) { prefs, encryptedValue ->
                prefs[ACCESS_TOKEN] = encryptedValue
            }
        }
        refreshToken?.let { refreshTokenStr ->
            context.dataStore.secureEdit(refreshTokenStr) { prefs, encryptedData ->
                prefs[REFRESH_TOKEN] = encryptedData
            }
        }
    }

    suspend fun saveAccessTokens(accessToken: String?, refreshToken: String?) {
        context.dataStore.edit { preferences ->
            accessToken?.let { preferences[ACCESS_TOKEN] = it }
            refreshToken?.let { preferences[REFRESH_TOKEN] = it }
        }
    }

    suspend fun clear() {
        context.dataStore.edit { preferences ->
            preferences.clear()
        }
    }

    private inline fun <reified T> Flow<Preferences>.secureMap(
        crossinline fetchValue: (value: Preferences) -> String?
    ): Flow<T?> {
        return map {
            val encrypted = fetchValue(it)
            encrypted?.let { encryptedValue ->
                val decryptedValue = appSecurity.decryptData(
                    encryptedData = encryptedValue.split(bytesToStringSeparator)
                        .map { symbol ->
                            symbol.toByte()
                        }.toByteArray()
                )
                json.decodeFromString(decryptedValue)
            }
        }
    }

    private suspend inline fun <reified T> DataStore<Preferences>.secureEdit(
        value: T,
        crossinline editStore: (MutablePreferences, String) -> Unit
    ) {
        edit {
            val encryptedValue = appSecurity.encryptData(text = json.encodeToString(value))
            editStore.invoke(it, encryptedValue.joinToString(bytesToStringSeparator))
        }
    }

    companion object {
        private val ACCESS_TOKEN = stringPreferencesKey("key_access_token")
        private val REFRESH_TOKEN = stringPreferencesKey("key_refresh_token")
    }
}