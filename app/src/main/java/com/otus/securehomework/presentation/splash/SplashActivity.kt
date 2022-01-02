package com.otus.securehomework.presentation.splash

import android.os.Bundle
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.auth.AuthPromptHost
import androidx.lifecycle.*
import com.otus.securehomework.R
import com.otus.securehomework.data.source.local.UserPreferences
import com.otus.securehomework.presentation.auth.AuthActivity
import com.otus.securehomework.presentation.home.HomeActivity
import com.otus.securehomework.presentation.startNewActivity
import com.otus.securehomework.security.AppSecurity
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class SplashActivity : AppCompatActivity() {

    private val viewModel by viewModels<SplashViewModel>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_splash)

        observeEvents()
    }

    private fun observeEvents() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch {
                    viewModel.shouldUseBiometric.collect { useBiometrics ->
                        if (useBiometrics) {
                            viewModel.initiateBiometricLogin(AuthPromptHost(this@SplashActivity)) {
                                startNewActivity(HomeActivity::class.java)
                            }
                        }
                    }
                }

                launch {
                    viewModel.shouldUseLoginForm.collect { useLoginForm ->
                        if (useLoginForm) {
                            startNewActivity(AuthActivity::class.java)
                        }
                    }
                }
            }
        }
    }
}