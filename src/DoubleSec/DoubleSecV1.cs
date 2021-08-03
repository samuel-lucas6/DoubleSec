using System;
using Sodium;
using System.Security.Cryptography;

/*
    DoubleSec: A simple, double-paranoid encryption library.
    Copyright (c) 2021 Samuel Lucas

    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

namespace DoubleSec
{
    public static class DoubleSecV1
    {
        public static byte[] EncryptUsingPassword(byte[] password, byte[] message)
        {
            ParameterValidation.Password(password);
            ParameterValidation.Message(message);
            byte[] salt = SodiumCore.GetRandomBytes(Constants.SaltSize);
            var (xChaCha20Key, aesCTRKey, hmacKey, blake2bKey) = KeyDerivation.Password(password, salt);
            return Encrypt(message, salt, xChaCha20Key, aesCTRKey, hmacKey, blake2bKey);
        }

        public static byte[] EncryptUsingSharedSecret(byte[] sharedSecret, byte[] message)
        {
            ParameterValidation.SharedSecret(sharedSecret);
            ParameterValidation.Message(message);
            byte[] salt = SodiumCore.GetRandomBytes(Constants.SaltSize);
            var (xChaCha20Key, aesCTRKey, hmacKey, blake2bKey) = KeyDerivation.SharedSecret(sharedSecret, salt);
            return Encrypt(message, salt, xChaCha20Key, aesCTRKey, hmacKey, blake2bKey);
        }

        private static byte[] Encrypt(byte[] message, byte[] salt, byte[] xChaCha20Key, byte[] aesCTRKey, byte[] hmacKey, byte[] blake2bKey)
        {
            byte[] nonce = SodiumCore.GetRandomBytes(Constants.NonceSize);
            byte[] iv = SodiumCore.GetRandomBytes(Constants.IVSize);
            byte[] innerCiphertext = StreamEncryption.EncryptXChaCha20(message, nonce, xChaCha20Key);
            Arrays.ZeroMemory(xChaCha20Key);
            innerCiphertext = Arrays.Concat(nonce, innerCiphertext);
            Arrays.ZeroMemory(nonce);
            byte[] outerCiphertext = AesCTR.Encrypt(innerCiphertext, iv, aesCTRKey);
            Arrays.ZeroMemory(aesCTRKey);
            outerCiphertext = Arrays.Concat(Constants.MagicBytes, Constants.Version, salt, iv, outerCiphertext);
            var hmacTag = new byte[Constants.TagSize];
            using (var hmac = new HMACSHA512(hmacKey))
            {
                hmacTag = hmac.ComputeHash(outerCiphertext);
            }
            Arrays.ZeroMemory(hmacKey);
            byte[] blake2bTag = GenericHash.Hash(outerCiphertext, blake2bKey, Constants.TagSize);
            Arrays.ZeroMemory(blake2bKey);
            return Arrays.Concat(outerCiphertext, hmacTag, blake2bTag);
        }

        public static byte[] DecryptUsingPassword(byte[] password, byte[] ciphertext)
        {
            ParameterValidation.Password(password);
            ParameterValidation.Ciphertext(ciphertext);
            byte[] salt = GetSalt(ciphertext);
            var (xChaCha20Key, aesCTRKey, hmacKey, blake2bKey) = KeyDerivation.Password(password, salt);
            byte[] ciphertextWithoutTags = ValidateTags(ciphertext, hmacKey, blake2bKey);
            byte[] iv = GetIV(ciphertextWithoutTags);
            byte[] ciphertextWithoutHeaders = GetCiphertextWithoutHeaders(ciphertextWithoutTags);
            return Decrypt(ciphertextWithoutHeaders, iv, aesCTRKey, xChaCha20Key);
        }

        public static byte[] DecryptUsingSharedSecret(byte[] sharedSecret, byte[] ciphertext)
        {
            ParameterValidation.SharedSecret(sharedSecret);
            ParameterValidation.Ciphertext(ciphertext);
            byte[] salt = GetSalt(ciphertext);
            var (xChaCha20Key, aesCTRKey, hmacKey, blake2bKey) = KeyDerivation.SharedSecret(sharedSecret, salt);
            byte[] ciphertextWithoutTags = ValidateTags(ciphertext, hmacKey, blake2bKey);
            byte[] iv = GetIV(ciphertextWithoutTags);
            byte[] ciphertextWithoutHeaders = GetCiphertextWithoutHeaders(ciphertextWithoutTags);
            return Decrypt(ciphertextWithoutHeaders, iv, aesCTRKey, xChaCha20Key);
        }

        private static byte[] GetSalt(byte[] ciphertext)
        {
            var salt = new byte[Constants.SaltSize];
            Array.Copy(ciphertext, Constants.MagicBytes.Length + Constants.Version.Length, salt, destinationIndex: 0, salt.Length);
            return salt;
        }

        private static byte[] ValidateTags(byte[] ciphertext, byte[] hmacKey, byte[] blake2bKey)
        {
            var authenticationTags = new byte[Constants.TagSize * 2];
            Array.Copy(ciphertext, ciphertext.Length - authenticationTags.Length, authenticationTags, destinationIndex: 0, authenticationTags.Length);
            var ciphertextWithoutTags = new byte[ciphertext.Length - authenticationTags.Length];
            Array.Copy(ciphertext, ciphertextWithoutTags, ciphertextWithoutTags.Length);
            var computedHMACTag = new byte[Constants.TagSize];
            using (var hmac = new HMACSHA512(hmacKey))
            {
                computedHMACTag = hmac.ComputeHash(ciphertextWithoutTags);
            }
            Arrays.ZeroMemory(hmacKey);
            byte[] computedBLAKE2bTag = GenericHash.Hash(ciphertextWithoutTags, blake2bKey, Constants.TagSize);
            Arrays.ZeroMemory(blake2bKey);
            byte[] computedTags = Arrays.Concat(computedHMACTag, computedBLAKE2bTag);
            bool validTags = Utilities.Compare(authenticationTags, computedTags);
            if (!validTags)
            {
                throw new CryptographicException(Constants.DecryptionError);
            }
            return ciphertextWithoutTags;
        }

        private static byte[] GetIV(byte[] ciphertextWithoutTags)
        {
            var iv = new byte[Constants.IVSize];
            Array.Copy(ciphertextWithoutTags, Constants.MagicBytes.Length + Constants.Version.Length + Constants.SaltSize, iv, destinationIndex: 0, iv.Length);
            return iv;
        }

        private static byte[] GetCiphertextWithoutHeaders(byte[] ciphertextWithoutTags)
        {
            var ciphertextWithoutHeaders = new byte[ciphertextWithoutTags.Length - Constants.MagicBytes.Length - Constants.Version.Length - Constants.SaltSize - Constants.IVSize];
            Array.Copy(ciphertextWithoutTags, Constants.MagicBytes.Length + Constants.Version.Length + Constants.SaltSize + Constants.IVSize, ciphertextWithoutHeaders, destinationIndex: 0, ciphertextWithoutHeaders.Length);
            return ciphertextWithoutHeaders;
        }

        private static byte[] Decrypt(byte[] ciphertext, byte[] iv, byte[] aesCTRKey, byte[] xChaCha20Key)
        {
            byte[] innerCiphertextWithNonce = AesCTR.Decrypt(ciphertext, iv, aesCTRKey);
            Arrays.ZeroMemory(aesCTRKey);
            var nonce = new byte[Constants.NonceSize];
            Array.Copy(innerCiphertextWithNonce, nonce, nonce.Length);
            var innerCiphertext = new byte[innerCiphertextWithNonce.Length - nonce.Length];
            Array.Copy(innerCiphertextWithNonce, nonce.Length, innerCiphertext, destinationIndex: 0, innerCiphertext.Length);
            byte[] plaintext = StreamEncryption.DecryptXChaCha20(innerCiphertext, nonce, xChaCha20Key);
            Arrays.ZeroMemory(xChaCha20Key);
            return plaintext;
        }
    }
}
