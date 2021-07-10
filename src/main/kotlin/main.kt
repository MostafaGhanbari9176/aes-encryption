import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

private val aesKey =
    byteArrayOf(0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30)

fun main(args: Array<String>) {
    println("Please Inter A Text")

    val input = "readLine()"

    println("--------- Encrypted Text ---------")
    val encryptedText = encrypt(input.toString())
    println(encryptedText)

    println("--------- Decrypted Text ---------")
    val decryptedText = decrypt(encryptedText)
    println(decryptedText)
}

private fun encrypt(plainText: String): String {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(
        Cipher.ENCRYPT_MODE, SecretKeySpec(aesKey, "AES"),
        IvParameterSpec(List<Byte>(16){0}.toByteArray())
    )
    val cipherOutPut = cipher.doFinal(plainText.toByteArray())

    val base64 = Base64.getEncoder().encode(cipherOutPut)

    return String(base64)
}

private fun decrypt(base64Text: String): String {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(
        Cipher.DECRYPT_MODE, SecretKeySpec(aesKey, "AES"),
        IvParameterSpec(List<Byte>(16){0}.toByteArray())
    )

    val cipherText = Base64.getDecoder().decode(base64Text)

    val cipherOutPut = cipher.doFinal(cipherText)

    return String(cipherOutPut)
}