package com.otus.securehomework.data.dto

data class EncryptedObject(
    val cipheredText: ByteArray,
    val initializationVector: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as EncryptedObject

        if (!cipheredText.contentEquals(other.cipheredText)) return false
        if (!initializationVector.contentEquals(other.initializationVector)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = cipheredText.contentHashCode()
        result = 31 * result + initializationVector.contentHashCode()
        return result
    }
}