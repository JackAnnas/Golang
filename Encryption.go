package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/sha256"
    "encoding/hex"
    "encoding/base64"
    "fmt"
    "strings"
    "time"
)

func byteArrToStr(ba []byte) string {
    return hex.EncodeToString(ba)
}

func strToByteArr(s string) []byte {
    data, _ := hex.DecodeString(s)
    return data
}

func encryptString(plainText string, key, iv []byte) string {
    block, _ := aes.NewCipher(key)
    encrypter := cipher.NewCFBEncrypter(block, iv)
    cipherText := make([]byte, len(plainText))
    encrypter.XORKeyStream(cipherText, []byte(plainText))
    return byteArrToStr(cipherText)
}

func decryptString(cipherText string, key, iv []byte) string {
    block, _ := aes.NewCipher(key)
    decrypter := cipher.NewCFBDecrypter(block, iv)
    cipherTextBytes := strToByteArr(cipherText)
    decrypter.XORKeyStream(cipherTextBytes, cipherTextBytes)
    return string(cipherTextBytes)
}

func generateIVKey() string {
    return strings.ReplaceAll(strings.ReplaceAll(time.Now().String(), " ", ""), ":", "")
}

func sha256Hash(input string) string {
    data := sha256.Sum256([]byte(input))
    return hex.EncodeToString(data[:])
}

func encrypt(message, encKey, iv string) string {
    key := []byte(sha256Hash(encKey)[:32])
    ivBytes := []byte(sha256Hash(iv)[:16])
    return encryptString(message, key, ivBytes)
}

func decrypt(message, encKey, iv string) string {
    key := []byte(sha256Hash(encKey)[:32])
    ivBytes := []byte(sha256Hash(iv)[:16])
    return decryptString(message, key, ivBytes)
}

func unixToDate(unixTimeStamp float64) time.Time {
    return time.Unix(int64(unixTimeStamp), 0)
}

func main() {
    // You can test the functions here if needed
    fmt.Println("Testing encryption and decryption:")
    message := "Hello, world!"
    encKey := "encryptionKey"
    iv := "1234567890123456"
    encrypted := encrypt(message, encKey, iv)
    fmt.Println("Encrypted:", encrypted)
    decrypted := decrypt(encrypted, encKey, iv)
    fmt.Println("Decrypted:", decrypted)

    fmt.Println("Testing SHA256 hash:")
    input := "Hello, Golang!"
    hashed := sha256Hash(input)
    fmt.Println("SHA256 Hash:", hashed)
}
