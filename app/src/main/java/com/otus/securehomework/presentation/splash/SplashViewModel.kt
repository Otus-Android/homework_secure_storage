package com.otus.securehomework.presentation.splash

import androidx.biometric.auth.AuthPromptHost
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.otus.securehomework.data.source.local.UserPreferences
import com.otus.securehomework.security.biometrics.BiometricAuthenticator
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class SplashViewModel @Inject constructor(
    private val userPreferences: UserPreferences,
    private val biometricAuthenticator: BiometricAuthenticator
) : ViewModel() {

    private val biometricEnabled: Flow<Boolean>
        get() = userPreferences.isBiometricsEnabled

    private val accessTokenFlow: Flow<String?>
        get() = userPreferences.accessToken

    val shouldUseBiometric: Flow<Boolean>
        get() = accessTokenFlow.combine(biometricEnabled) { accessToken, biometrics ->
            !accessToken.isNullOrEmpty() && biometrics && biometricAuthenticator.canAuthenticate()
        }

    val shouldUseLoginForm: Flow<Boolean>
        get() = accessTokenFlow.combine(biometricEnabled) { accessToken, biometrics ->
            accessToken.isNullOrEmpty() || !biometrics
        }

    fun initiateBiometricLogin(host: AuthPromptHost, onUserAuthenticated: () -> Unit) {
        viewModelScope.launch {
            biometricAuthenticator.initiateBiometricPrompt(host)
            onUserAuthenticated()
        }
    }
}