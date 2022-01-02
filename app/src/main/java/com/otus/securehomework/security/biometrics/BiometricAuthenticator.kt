package com.otus.securehomework.security.biometrics

import android.content.Context
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.auth.AuthPromptHost
import androidx.biometric.auth.Class2BiometricAuthPrompt
import androidx.biometric.auth.Class3BiometricAuthPrompt
import androidx.core.content.ContextCompat
import com.otus.securehomework.security.AppSecurity
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject


class BiometricAuthenticator @Inject constructor(
    @ApplicationContext private val context: Context,
    private val appSecurity: AppSecurity
) {
    private val executor = ContextCompat.getMainExecutor(context)
    private val biometricManager by lazy {
        BiometricManager.from(context)
    }

    suspend fun initiateBiometricPrompt(host: AuthPromptHost) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && canAuthenticateResult(BIOMETRIC_STRONG)) {
            strongAuthenticationPrompt(host)
        } else if (canAuthenticateResult(BIOMETRIC_WEAK)) {
            weakAuthenticationPrompt(host)
        }
    }

    fun canAuthenticate(): Boolean {
        return canAuthenticateResult(BIOMETRIC_STRONG) || canAuthenticateResult(BIOMETRIC_WEAK)
    }

    private fun canAuthenticateResult(type: Int): Boolean {
        return biometricManager.canAuthenticate(type) == BiometricManager.BIOMETRIC_SUCCESS
    }

    private suspend fun strongAuthenticationPrompt(host: AuthPromptHost) {
        Class3BiometricAuthPrompt.Builder("Authenticate via biometrics", "Cancel")
            .setConfirmationRequired(true)
            .build()
            .authenticate(host, appSecurity.encryptor, executor)
    }

    private suspend fun weakAuthenticationPrompt(host: AuthPromptHost) {
        Class2BiometricAuthPrompt.Builder("Authenticate via biometrics", "Cancel")
            .setConfirmationRequired(true)
            .build()
            .authenticate(host, executor)
    }
}