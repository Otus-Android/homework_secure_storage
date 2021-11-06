package com.otus.securehomework.presentation.home

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import com.otus.securehomework.data.Response
import com.otus.securehomework.data.dto.LoginResponse
import com.otus.securehomework.data.dto.User
import com.otus.securehomework.data.repository.UserRepository
import com.otus.securehomework.presentation.BaseViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class HomeViewModel
@Inject constructor(
    private val repository: UserRepository
) : BaseViewModel(repository) {

    private val _user: MutableLiveData<Response<LoginResponse>> = MutableLiveData()
    val user: LiveData<Response<LoginResponse>>
        get() = _user
    private val _isUserValid: MutableLiveData<Boolean> = MutableLiveData()
    val isUserValid: LiveData<Boolean>
        get() = _isUserValid

    fun getUser() = viewModelScope.launch {
        _user.value = Response.Loading
        _user.value = repository.getUser()
    }

    fun checkAccessToken(user: User) = viewModelScope.launch {
        _isUserValid.value = repository.isUserValid(user.access_token)
    }
}
