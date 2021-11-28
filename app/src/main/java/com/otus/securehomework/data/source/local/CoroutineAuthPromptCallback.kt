package com.otus.securehomework.data.source.local

import androidx.biometric.BiometricPrompt
import androidx.biometric.auth.AuthPromptCallback
import androidx.biometric.auth.AuthPromptErrorException
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.CancellableContinuation
import kotlin.coroutines.resumeWithException

/**
 * взято с репозитория
 * https://github.com/vitalyraevsky/otus_security
 */
internal class CoroutineAuthPromptCallback(
    private val continuation: CancellableContinuation<BiometricPrompt.AuthenticationResult>
) : AuthPromptCallback() {

    override fun onAuthenticationError(
        activity: FragmentActivity?,
        errorCode: Int,
        errString: CharSequence
    ) {
        continuation.resumeWithException(AuthPromptErrorException(errorCode, errString))
    }

    override fun onAuthenticationSucceeded(
        activity: FragmentActivity?,
        result: BiometricPrompt.AuthenticationResult
    ) {
        continuation.resumeWith(Result.success(result))
    }

    override fun onAuthenticationFailed(activity: FragmentActivity?) {
        // Stub
    }
}