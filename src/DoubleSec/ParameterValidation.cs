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
    internal static class ParameterValidation
    {
        internal static void Password(byte[] password)
        {
            if (password == null || password.Length == 0)
            { 
                throw new ArgumentException("Password cannot be null or empty."); 
            }
        }

        internal static void Message(byte[] message)
        {
            if (message == null || message.Length == 0) 
            { 
                throw new ArgumentException("Message cannot be null or empty."); 
            }
        }

        internal static void SharedSecret(byte[] sharedSecret)
        {
            if (sharedSecret == null || sharedSecret.Length == 0) 
            { 
                throw new ArgumentException("Shared secret cannot be null or empty."); 
            }
        }

        internal static void Ciphertext(byte[] ciphertext)
        {
            if (ciphertext == null || ciphertext.Length == 0)
            {
                throw new ArgumentException("Ciphertext cannot be null or empty.");
            }
            var magicBytes = new byte[Constants.MagicBytes.Length];
            Array.Copy(ciphertext, magicBytes, magicBytes.Length);
            bool validMagicBytes = Utilities.Compare(magicBytes, Constants.MagicBytes);
            if (!validMagicBytes)
            {
                throw new ArgumentException("Invalid magic bytes.");
            }
            var version = new byte[Constants.Version.Length];
            Array.Copy(ciphertext, magicBytes.Length, version, destinationIndex: 0, version.Length);
            bool validVersion = Utilities.Compare(version, Constants.Version);
            if (!validVersion)
            {
                throw new ArgumentException("Invalid version.");
            }
        }
    }
}
