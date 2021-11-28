package com.otus.securehomework.presentation.home

import androidx.biometric.auth.AuthPromptHost
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import com.otus.securehomework.data.Response
import com.otus.securehomework.data.dto.LoginResponse
import com.otus.securehomework.data.repository.UserRepository
import com.otus.securehomework.data.source.local.AuthHandler
import com.otus.securehomework.data.source.local.SecuredPrefs
import com.otus.securehomework.presentation.BaseViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class HomeViewModel
@Inject constructor(
    private val repository: UserRepository,
    private val prefs: SecuredPrefs,
    private val authHandler: AuthHandler
) : BaseViewModel(repository) {

    private val _user: MutableLiveData<Response<LoginResponse>> = MutableLiveData()
    val user: LiveData<Response<LoginResponse>>
        get() = _user

    private val _hasBiometric: MutableLiveData<Boolean> = MutableLiveData()
    val hasBiometric: LiveData<Boolean>
        get() = _hasBiometric

    fun switchBiometric(host: AuthPromptHost) = viewModelScope.launch {
        if (_hasBiometric.value == true) {
            prefs.clearBiometricsState()
        } else {
            authHandler.updateBiometricsState(host)
        }
        _hasBiometric.value = prefs.isBiometricsEnabled.first()
    }

    fun getUser() = viewModelScope.launch {
        _user.value = Response.Loading
        _user.value = repository.getUser()
    }
}