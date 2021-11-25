package com.otus.securehomework.data.repository

import com.otus.securehomework.data.Response
import com.otus.securehomework.data.dto.LoginResponse
import com.otus.securehomework.data.dto.User
import com.otus.securehomework.data.source.local.UserPreferences
import com.otus.securehomework.data.source.network.AuthApi
import javax.inject.Inject

class AuthRepository
@Inject constructor(
    private val api: AuthApi,
    private val preferences: UserPreferences,
) : BaseRepository(api) {

    suspend fun login(
        email: String,
        password: CharSequence
    ): Response<LoginResponse> {
        return Response.Success(
            LoginResponse(
                User(
                    1,
                    "Vasya",
                    email,
                    true,
                    "",
                    "",
                    "access",
                    "refresh"
                )
            )
        )
        //return safeApiCall { api.login(email, password.toString()) }
    }

    suspend fun saveAccessTokens(accessToken: CharSequence?, refreshToken: CharSequence?) {
        preferences.saveAccessTokens(accessToken, refreshToken)
    }
}
