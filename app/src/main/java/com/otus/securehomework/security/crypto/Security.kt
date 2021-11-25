package com.otus.securehomework.security.crypto

import java.math.BigInteger
import java.security.MessageDigest
import javax.inject.Inject

/**
 *
 * @author Юрий Польщиков on 05.11.2021
 */
class Security @Inject constructor() {

    /* Хеширование
    https://developer.android.com/reference/kotlin/java/security/MessageDigest
    */
    fun sha256(plaintext: CharSequence): String {
        return createHash(plaintext.toString(), "SHA-256")
    }

    private fun createHash(plaintext: CharSequence, type: String): String {
        val md = MessageDigest.getInstance(type)
        val bigInt = BigInteger(1, md.digest(plaintext.toString().toByteArray(Charsets.UTF_8)))
        return String.format("%032x", bigInt)
    }
}
