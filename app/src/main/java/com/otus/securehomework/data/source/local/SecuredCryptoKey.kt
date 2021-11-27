package com.otus.securehomework.data.source.local

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import androidx.security.crypto.MasterKey
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject

class SecuredCryptoKey @Inject constructor(@ApplicationContext val context: Context) {

    val masterKey: MasterKey
        get() = MasterKey.Builder(context).also {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) setMasterKeyParameters(it)
            else it.setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        }.build()

    @RequiresApi(Build.VERSION_CODES.M)
    private fun setMasterKeyParameters(masterKeyBuilder: MasterKey.Builder): MasterKey.Builder {
        return masterKeyBuilder.setKeyGenParameterSpec(
            KeyGenParameterSpec.Builder(
                MasterKey.DEFAULT_MASTER_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
    }
}