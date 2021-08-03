using System;
using Sodium;
using System.Collections.Generic;
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
    internal static class AesCTR
    {
        internal static byte[] Encrypt(byte[] message, byte[] nonce, byte[] key)
        {
            var counter = new byte[nonce.Length];
            Array.Copy(nonce, counter, nonce.Length);
            using (var aes = new AesCryptoServiceProvider() { Mode = CipherMode.ECB, Padding = PaddingMode.None })
            {
                var emptyIV = new byte[counter.Length];
                using (var encryptor = aes.CreateEncryptor(key, emptyIV))
                {
                    int iterations = (int)Math.Ceiling((decimal)message.Length / counter.Length);
                    var keystream = new List<byte>();
                    var keystreamBlock = new byte[counter.Length];
                    for (int i = 0; i < iterations; i++)
                    {
                        encryptor.TransformBlock(counter, inputOffset: 0, counter.Length, keystreamBlock, outputOffset: 0);
                        counter = Utilities.Increment(counter);
                        keystream.AddRange(keystreamBlock);
                    }
                    return Xor(message, keystream);
                }
            }
        }

        internal static byte[] Decrypt(byte[] ciphertext, byte[] nonce, byte[] key)
        {
            return Encrypt(ciphertext, nonce, key);
        }

        private static byte[] Xor(byte[] message, List<byte> keystream)
        {
            for (int i = 0; i < message.Length; i++)
            {
                message[i] = (byte)(message[i] ^ keystream[i]);
            }
            return message;
        }
    }
}
