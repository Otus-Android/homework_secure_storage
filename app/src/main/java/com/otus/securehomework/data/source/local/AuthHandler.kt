package com.otus.securehomework.data.source.local

import android.content.Context
import androidx.biometric.BiometricManager
import android.os.Build
import android.util.Base64
import androidx.annotation.RequiresApi
import androidx.biometric.auth.AuthPromptHost
import androidx.biometric.auth.Class2BiometricAuthPrompt
import androidx.biometric.auth.Class3BiometricAuthPrompt
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject

class AuthHandler @Inject constructor(
    @ApplicationContext private val context: Context,
    private val authCipher: AuthCipher,
    private val prefs: SecuredPrefs
) {

    suspend fun updateBiometricsState(host: AuthPromptHost) {
        prefs.updateBiometricsState(provideAuthParameters(host))
    }

    suspend fun getBiometricsState(host: AuthPromptHost): Boolean = provideAuthParameters(host)

    private suspend fun provideAuthParameters(host: AuthPromptHost): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
            && canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            strongBiometricAuth(host)
        } else if (canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK)) {
            weakBiometricAuth(host)
        } else false
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private suspend fun strongBiometricAuth(host: AuthPromptHost): Boolean {
       Class3BiometricAuthPrompt.Builder("Strong biometry", "dismiss")
            .setSubtitle("login")
            .setDescription("scan")
            .setConfirmationRequired(true)
            .build()
            .authenticate(host, authCipher.encryptObject)
        return true
    }

    private suspend fun weakBiometricAuth(host: AuthPromptHost): Boolean {
        Class2BiometricAuthPrompt.Builder("Weak biometry", "dismiss")
            .setSubtitle("login")
            .setDescription("scan")
            .setConfirmationRequired(true)
            .build()
            .authenticate(host)
        return true
    }

    private fun canAuthenticate(authenticator: Int) = BiometricManager.from(context)
        .canAuthenticate(authenticator) == BiometricManager.BIOMETRIC_SUCCESS

    fun ByteArray.toBase64(flags: Int = Base64.DEFAULT): String = Base64.encodeToString(this, flags)
    fun String.fromBase64(flags: Int = Base64.DEFAULT): ByteArray = Base64.decode(this, flags)
}