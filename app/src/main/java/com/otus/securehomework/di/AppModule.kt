package com.otus.securehomework.di

import android.content.Context
import com.otus.securehomework.data.repository.AuthRepository
import com.otus.securehomework.data.repository.UserRepository
import com.otus.securehomework.data.source.local.UserPreferences
import com.otus.securehomework.data.source.network.AuthApi
import com.otus.securehomework.data.source.network.UserApi
import com.otus.securehomework.security.crypto.CryptographyManager
import com.otus.securehomework.security.crypto.CryptographyManagerImpl
import dagger.Module
import dagger.Provides
import dagger.Reusable
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Reusable
    @Provides
    fun provideCryptographyManager(@ApplicationContext context: Context): CryptographyManager {
        return CryptographyManagerImpl(context)
    }

    @Singleton
    @Provides
    fun provideRemoteDataSource(): RemoteDataSource {
        return RemoteDataSource()
    }

    @Provides
    fun provideAuthApi(
        remoteDataSource: RemoteDataSource,
        userPreferences: UserPreferences
    ): AuthApi {
        return remoteDataSource.buildApi(AuthApi::class.java, userPreferences)
    }

    @Provides
    fun provideUserApi(
        remoteDataSource: RemoteDataSource,
        userPreferences: UserPreferences
    ): UserApi {
        return remoteDataSource.buildApi(UserApi::class.java, userPreferences)
    }

    @Singleton
    @Provides
    fun provideUserPreferences(
        cryptographyManager: CryptographyManager,
    ): UserPreferences {
        return UserPreferences(cryptographyManager)
    }

    @Provides
    fun provideAuthRepository(
        authApi: AuthApi,
        userPreferences: UserPreferences,
    ): AuthRepository {
        return AuthRepository(authApi, userPreferences)
    }

    @Provides
    fun provideUserRepository(
        userApi: UserApi,
        userPreferences: UserPreferences,
    ): UserRepository {
        return UserRepository(userApi, userPreferences)
    }
}
