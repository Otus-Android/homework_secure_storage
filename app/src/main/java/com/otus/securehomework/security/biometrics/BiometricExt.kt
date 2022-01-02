package com.otus.securehomework.security.biometrics

import androidx.biometric.BiometricPrompt
import androidx.biometric.auth.AuthPromptHost
import androidx.biometric.auth.Class2BiometricAuthPrompt
import androidx.biometric.auth.Class3BiometricAuthPrompt
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.concurrent.Executor

suspend fun Class3BiometricAuthPrompt.authenticate(
    host: AuthPromptHost,
    crypto: BiometricPrompt.CryptoObject?,
    executor: Executor
): BiometricPrompt.AuthenticationResult {
    return suspendCancellableCoroutine { continuation ->
        val authPrompt = startAuthentication(
            host,
            crypto,
            executor,
            CoroutineAuthPromptCallback(continuation)
        )
        continuation.invokeOnCancellation {
            authPrompt.cancelAuthentication()
        }
    }
}

suspend fun Class2BiometricAuthPrompt.authenticate(
    host: AuthPromptHost,
    executor: Executor
): BiometricPrompt.AuthenticationResult {
    return suspendCancellableCoroutine { continuation ->
        val authPrompt = startAuthentication(
            host,
            executor,
            CoroutineAuthPromptCallback(continuation)
        )
        continuation.invokeOnCancellation {
            authPrompt.cancelAuthentication()
        }
    }
}