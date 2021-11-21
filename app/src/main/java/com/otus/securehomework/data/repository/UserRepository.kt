package com.otus.securehomework.data.repository

import com.otus.securehomework.data.dto.LoginResponse
import com.otus.securehomework.data.dto.User
import com.otus.securehomework.data.source.local.UserPreferences
import com.otus.securehomework.data.source.network.UserApi
import kotlinx.coroutines.flow.first
import javax.inject.Inject

class UserRepository @Inject constructor(
    private val api: UserApi,
    private val preferences: UserPreferences
) : BaseRepository(api) {

    suspend fun getUser() = safeApiCall { LoginResponse(
        User(
            1,
            "Vasya",
            "email",
            true,
            "",
            "",
            "access",
            "refresh"
        )
    ) }

    suspend fun isUserValid(accessToken: CharSequence?): Boolean {
        return accessToken == preferences.accessToken.first()
    }
}
