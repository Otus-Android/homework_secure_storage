package com.otus.securehomework.data.repository

import com.otus.securehomework.data.source.local.UserPreferences
import com.otus.securehomework.data.source.network.UserApi
import kotlinx.coroutines.flow.first
import javax.inject.Inject

class UserRepository @Inject constructor(
    private val api: UserApi,
    private val preferences: UserPreferences
) : BaseRepository(api) {

    suspend fun getUser() = safeApiCall { api.getUser() }

    suspend fun isUserValid(accessToken: CharSequence?): Boolean {
        return accessToken == preferences.accessToken.first()
    }
}
