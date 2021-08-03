using System.Text;

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
    internal static class Constants
    {
        internal const int SaltSize = 16;
        internal const int Iterations = 12;
        internal const int MemorySize = 268435456;
        internal const int OutputLength = 192;
        internal const int EncryptionKeySize = 32;
        internal const int MACKeySize = 64;
        internal const int NonceSize = 24;
        internal const int IVSize = 16;
        internal const int TagSize = 64;
        internal static readonly byte[] MagicBytes = Encoding.UTF8.GetBytes("DOUBLESEC");
        internal static readonly byte[] Version = BitConversion.GetBytes(1);
        internal static readonly byte[] Personal = Encoding.UTF8.GetBytes("___DoubleSec!___");
        internal static readonly byte[] XChaCha20Context = Encoding.UTF8.GetBytes("DoubleSec 9:23 02/08/21 XChaCha20");
        internal static readonly byte[] AesCTRContext = Encoding.UTF8.GetBytes("DoubleSec 9:24 02/08/21 AES-CTR");
        internal static readonly byte[] HMACContext = Encoding.UTF8.GetBytes("DoubleSec 9:25 02/08/21 HMAC-SHA512");
        internal static readonly byte[] BLAKE2bContext = Encoding.UTF8.GetBytes("DoubleSec 9:26 02/08/21 BLAKE2b-512");
        internal const string DecryptionError = "The password/key is incorrect, or this ciphertext has been tampered with.";
    }
}
