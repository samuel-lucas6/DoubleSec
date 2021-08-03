using System;
using Sodium;

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
    internal static class KeyDerivation
    {
        internal static (byte[] xChaCha20Key, byte[] aesCTRKey, byte[] hmacKey, byte[] blake2bKey) Password(byte[] password, byte[] salt)
        {
            byte[] keys = PasswordHash.ArgonHashBinary(password, salt, Constants.Iterations, Constants.MemorySize, Constants.OutputLength, PasswordHash.ArgonAlgorithm.Argon_2ID13);
            var xChaCha20Key = new byte[Constants.EncryptionKeySize];
            Array.Copy(keys, xChaCha20Key, xChaCha20Key.Length);
            var aesCTRKey = new byte[Constants.EncryptionKeySize];
            Array.Copy(keys, xChaCha20Key.Length, aesCTRKey, destinationIndex: 0, aesCTRKey.Length);
            var hmacKey = new byte[Constants.MACKeySize];
            Array.Copy(keys, xChaCha20Key.Length + aesCTRKey.Length, hmacKey, destinationIndex: 0, hmacKey.Length);
            var blake2bKey = new byte[Constants.MACKeySize];
            Array.Copy(keys, xChaCha20Key.Length + aesCTRKey.Length + hmacKey.Length, blake2bKey, destinationIndex: 0, blake2bKey.Length);
            Arrays.ZeroMemory(keys);
            return (xChaCha20Key, aesCTRKey, hmacKey, blake2bKey);
        }

        internal static (byte[] xChaCha20Key, byte[] aesCTRKey, byte[] hmacKey, byte[] blake2bKey) SharedSecret(byte[] sharedSecret, byte[] salt)
        {
            var incrementedSalt = new byte[salt.Length];
            Array.Copy(salt, incrementedSalt, salt.Length);
            byte[] xChaCha20Key = GenericHash.HashSaltPersonal(Constants.XChaCha20Context, sharedSecret, incrementedSalt, Constants.Personal, Constants.EncryptionKeySize);
            incrementedSalt = Utilities.Increment(incrementedSalt);
            byte[] aesCTRKey = GenericHash.HashSaltPersonal(Constants.AesCTRContext, sharedSecret, incrementedSalt, Constants.Personal, Constants.EncryptionKeySize);
            incrementedSalt = Utilities.Increment(incrementedSalt);
            byte[] hmacKey = GenericHash.HashSaltPersonal(Constants.HMACContext, sharedSecret, incrementedSalt, Constants.Personal, Constants.MACKeySize);
            incrementedSalt = Utilities.Increment(incrementedSalt);
            byte[] blake2bKey = GenericHash.HashSaltPersonal(Constants.BLAKE2bContext, sharedSecret, incrementedSalt, Constants.Personal, Constants.MACKeySize);
            return (xChaCha20Key, aesCTRKey, hmacKey, blake2bKey);
        }
    }
}
