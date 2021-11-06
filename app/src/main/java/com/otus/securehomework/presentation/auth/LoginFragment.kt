package com.otus.securehomework.presentation.auth

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.*
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.widget.addTextChangedListener
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.Observer
import androidx.lifecycle.lifecycleScope
import com.otus.securehomework.R
import com.otus.securehomework.data.Response
import com.otus.securehomework.databinding.FragmentLoginBinding
import com.otus.securehomework.presentation.enable
import com.otus.securehomework.presentation.handleApiError
import com.otus.securehomework.presentation.home.HomeActivity
import com.otus.securehomework.presentation.startNewActivity
import com.otus.securehomework.presentation.visible
import com.otus.securehomework.security.crypto.CIPHERTEXT_WRAPPER_ACCESS_TOKEN
import com.otus.securehomework.security.crypto.CryptographyManager
import com.otus.securehomework.security.crypto.Security
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch
import java.util.concurrent.Executor
import javax.inject.Inject

/**
 * https://developer.android.com/training/sign-in/biometric-auth
 */
@AndroidEntryPoint
class LoginFragment : Fragment(R.layout.fragment_login) {

    private lateinit var binding: FragmentLoginBinding
    private val viewModel by viewModels<AuthViewModel>()

    @Inject
    lateinit var security: Security

    @Inject
    lateinit var cryptographyManager: CryptographyManager
    private val ciphertextWrapper
        get() = cryptographyManager.getCiphertextWrapperFromSharedPrefs(CIPHERTEXT_WRAPPER_ACCESS_TOKEN)

    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo

    @RequiresApi(Build.VERSION_CODES.N)
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding = FragmentLoginBinding.bind(view)

        binding.progressbar.visible(false)
        binding.buttonLogin.enable(false)

        viewModel.loginResponse.observe(viewLifecycleOwner, Observer {
            binding.progressbar.visible(it is Response.Loading)
            when (it) {
                is Response.Success -> {
                    val canAuthenticate = BiometricManager.from(requireContext()).canAuthenticate(BIOMETRIC_STRONG)
                    if (canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS) {
                        lifecycleScope.launch {
                            viewModel.saveAccessTokens(
                                it.value.user.access_token,
                                it.value.user.refresh_token
                            )
                            requireActivity().startNewActivity(HomeActivity::class.java)
                        }
                    } else {
                        Toast.makeText(
                            requireContext(),
                            "Can't authenticate without biometry - TO DO!", Toast.LENGTH_SHORT
                        )
                            .show()
                        // todo
                    }
                }
                is Response.Failure -> handleApiError(it) { login() }
            }
        })
        binding.editTextTextPassword.addTextChangedListener {
            val email = binding.editTextTextEmailAddress.text.toString().trim()
            binding.buttonLogin.enable(email.isNotEmpty() && it.toString().isNotEmpty())
        }
        binding.buttonLogin.setOnClickListener {
            login()
        }

        setBiometricPrompt()
        setBiometricPromptInfo()

        binding.buttonBiometrics.setOnClickListener {
            if (ciphertextWrapper != null && checkBiometricsCredentials()) {
                authenticateBiometric()
            }
            if (ciphertextWrapper == null) {
                Toast.makeText(
                    requireContext(),
                    "Authenticate with login and password first!", Toast.LENGTH_SHORT
                )
                    .show()
            }
        }
    }

    private fun login() {
        val email = binding.editTextTextEmailAddress.text.toString().trim()
        val password = binding.editTextTextPassword.text.trim()
        val hashedPassword = security.sha256(password)
        viewModel.login(email, hashedPassword)
    }

    private fun setBiometricPrompt() {
        val executor = ContextCompat.getMainExecutor(requireContext())
        biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(
                    errorCode: Int,
                    errString: CharSequence
                ) {
                    super.onAuthenticationError(errorCode, errString)
                    Toast.makeText(
                        requireContext(),
                        "Authentication error: $errString", Toast.LENGTH_SHORT
                    )
                        .show()
                }

                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult
                ) {
                    super.onAuthenticationSucceeded(result)
                    Toast.makeText(
                        requireContext(),
                        "Authentication succeeded!", Toast.LENGTH_SHORT
                    )
                        .show()

                    ciphertextWrapper?.let { textWrapper ->
                        result.cryptoObject?.cipher?.let {
                            val plainAccessToken = cryptographyManager.decryptData(textWrapper.ciphertext, it)
                            // Now that you have the token, you can query server for everything else
                            Log.d("MY_APP_TAG", "Decrypted Access Token: " + plainAccessToken)
                        }
                    }

                    requireActivity().startNewActivity(HomeActivity::class.java)
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(
                        requireContext(), "Authentication failed",
                        Toast.LENGTH_SHORT
                    )
                        .show()
                }
            })
    }

    /**
     * Allows user to authenticate using either a Class 3 biometric or
     * their lock screen credential (PIN, pattern, or password).
     */
    private fun setBiometricPromptInfo() {
        promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric login for my app")
            .setSubtitle("Log in using your biometric credential")
            .setNegativeButtonText("Use account password")
            // Can't call setNegativeButtonText() and
            // setAllowedAuthenticators(... or DEVICE_CREDENTIAL) at the same time.
            // .setNegativeButtonText("Use account password")
            //.setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            // Allows user to authenticate without performing an action, such as pressing a
            // button, after their biometric credential is accepted.
            //.setConfirmationRequired(false)
            .build()
    }

    private fun checkBiometricsCredentials(): Boolean {
        var checkResult = true
        val biometricManager = BiometricManager.from(this.requireContext())
        when (biometricManager.canAuthenticate(BIOMETRIC_STRONG or BIOMETRIC_WEAK or DEVICE_CREDENTIAL)) {
            BiometricManager.BIOMETRIC_SUCCESS ->
                Log.d("MY_APP_TAG", "App can authenticate using biometrics.")
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
                Log.e("MY_APP_TAG", "No biometric features available on this device.")
                checkResult = false
            }
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                Log.e("MY_APP_TAG", "Biometric features are currently unavailable.")
                checkResult = false
            }
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                // Prompts the user to create credentials that your app accepts.
                val enrollIntent = Intent(Settings.ACTION_BIOMETRIC_ENROLL).apply {
                    putExtra(
                        Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED,
                        BIOMETRIC_STRONG or BIOMETRIC_WEAK or DEVICE_CREDENTIAL
                    )
                }
                val startForResult = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
                    if (result.resultCode == Activity.RESULT_OK) {
                        checkResult = false
                    }
                }
                startForResult.launch(enrollIntent)
            }
        }
        return checkResult
    }

    @RequiresApi(Build.VERSION_CODES.N)
    private fun authenticateBiometric() {
        // Exceptions are unhandled within this snippet.
        ciphertextWrapper?.initializationVector?.let {
            val cipher = cryptographyManager.getInitializedCipherForDecryption(it)
            biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        }
        //biometricPrompt.authenticate(promptInfo)
    }
}
