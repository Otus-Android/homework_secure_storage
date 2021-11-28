package com.otus.securehomework.presentation.auth

import androidx.biometric.auth.AuthPromptHost
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.asLiveData
import androidx.lifecycle.viewModelScope
import com.otus.securehomework.data.Response
import com.otus.securehomework.data.dto.LoginResponse
import com.otus.securehomework.data.repository.AuthRepository
import com.otus.securehomework.data.source.local.AuthHandler
import com.otus.securehomework.data.source.local.SecuredPrefs
import com.otus.securehomework.presentation.BaseViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class AuthViewModel
@Inject constructor(
    private val prefs: SecuredPrefs,
    private val repository: AuthRepository,
    private val authHandler: AuthHandler
) : BaseViewModel(repository) {

    private val _loginResponse: MutableLiveData<Response<LoginResponse>> = MutableLiveData()
    val loginResponse: LiveData<Response<LoginResponse>>
        get() = _loginResponse

    private val _biometricsInput: MutableLiveData<Boolean> = MutableLiveData()
    val biometricsInput: LiveData<Boolean>
        get() = _biometricsInput

    val isBiometricsEnabled: LiveData<Boolean>
        get() = prefs.isBiometricsEnabled.asLiveData()

    fun login(
        email: String,
        password: String
    ) = viewModelScope.launch {
        _loginResponse.value = Response.Loading
        _loginResponse.value = repository.login(email, password)
    }

    fun saveAccessTokens(accessToken: String, refreshToken: String) {
        repository.saveAccessTokens(accessToken, refreshToken)
    }

    fun startBiometrics(host: AuthPromptHost) {
        viewModelScope.launch {
            try {
                _biometricsInput.value = authHandler.getBiometricsState(host)
            } catch (e: Exception) {
                _biometricsInput.value = false
            }
        }
    }
}