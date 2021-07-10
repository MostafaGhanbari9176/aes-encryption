import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

private val aesKey =
    byteArrayOf(0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30)

fun main(args: Array<String>) {
    showMenu()
}

fun showMenu() {
    println(".".repeat(30))
    println("Please Inter A Text")

    val input = readLine()

    if(input.isNullOrEmpty()){
        showMenu()
        return
    }

    println("--------- Encrypted AESBase64 Text ---------")
    val encryptedText = encrypt(input.toByteArray())
    println(String(encryptedText))

    println("--------- Decrypted Text ---------")
    val decryptedText = decrypt(encryptedText)
    println(String(decryptedText))

    showMenu()
}

private fun encrypt(rawData: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    //you must specify an IV value when doing CBC-mode encryption
    val iv = IvParameterSpec(List<Byte>(16){0}.toByteArray())
    cipher.init(
        Cipher.ENCRYPT_MODE, SecretKeySpec(aesKey, "AES"),
        iv
    )
    val cipherOutPut = cipher.doFinal(rawData)

    val base64 = Base64.getEncoder().encode(cipherOutPut)

    return base64
}

private fun decrypt(encryptedData: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    //you must specify an IV value when doing CBC-mode decryption
    //and use that same value when performing the CBC-mode encryption
    val iv = IvParameterSpec(List<Byte>(16){0}.toByteArray())
    cipher.init(
        Cipher.DECRYPT_MODE, SecretKeySpec(aesKey, "AES"),
        iv
    )

    val cipherText = Base64.getDecoder().decode(encryptedData)

    val cipherOutPut = cipher.doFinal(cipherText)

    return cipherOutPut
}