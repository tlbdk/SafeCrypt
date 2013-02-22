using System;
using System.Collections.Generic;
using System.Web;
using System.Security.Cryptography;
using System.IO;
using System.Text;
using System.Runtime.Remoting.Metadata.W3cXsd2001;

namespace SafeCrypt
{
    public class SymmetricEncryption
    {
        private readonly SymmetricAlgorithm _algorithm;
        private readonly byte[] _secretKey;

        public SymmetricEncryption(SymmetricAlgorithm algorithm, byte[] secretKey)
        {
            _algorithm = algorithm;
            _secretKey = secretKey;
        }

        public byte[] Encrypt(byte[] valueBytes, byte[] initializationVector)
        {
            bool generateRandomIV = initializationVector == null;
            if (generateRandomIV)
            {
                initializationVector = new byte[_algorithm.BlockSize / 8];
                RandomNumberGenerator rng = RandomNumberGenerator.Create();
                rng.GetBytes(initializationVector);
            }
            using (MemoryStream output = new MemoryStream())
            {
                if (generateRandomIV)
                {
                    output.Write(initializationVector, 0, initializationVector.Length);
                }
                using (CryptoStream cryptoOutput = new CryptoStream(output, _algorithm.CreateEncryptor(_secretKey, initializationVector), CryptoStreamMode.Write))
                {
                    cryptoOutput.Write(valueBytes, 0, valueBytes.Length);
                }

                return output.ToArray();
            }
        }

        public byte[] Decrypt(byte[] encryptedValue, byte[] initializationVector)
        {
            int dataOffset = 0;
            if (initializationVector == null)
            {
                initializationVector = new byte[_algorithm.BlockSize / 8];
                Buffer.BlockCopy(encryptedValue, 0, initializationVector, 0, initializationVector.Length);
                dataOffset = initializationVector.Length;
            }
            using (MemoryStream output = new MemoryStream())
            {
                using (CryptoStream cryptoOutput = new CryptoStream(output, _algorithm.CreateDecryptor(_secretKey, initializationVector), CryptoStreamMode.Write))
                {
                    cryptoOutput.Write(encryptedValue, dataOffset, encryptedValue.Length - dataOffset);
                }

                return output.ToArray();
            }
        }
    }

    public class KeyedHashValidation
    {
        private readonly KeyedHashAlgorithm _algorithm;

        public KeyedHashValidation(KeyedHashAlgorithm algorithm, byte[] secretKey)
        {
            _algorithm = algorithm;
            _algorithm.Key = secretKey;
        }

        public byte[] ComputeSignature(byte[] data)
        {
            return ComputeSignature(data, 0, data.Length);
        }

        private byte[] ComputeSignature(byte[] data, int offset, int count)
        {
            return _algorithm.ComputeHash(data, offset, count);
        }

        public byte[] Sign(byte[] data)
        {
            int hashLength = _algorithm.HashSize / 8;
            int signedMessageLength = data.Length + hashLength;
            byte[] signedMessage = new byte[signedMessageLength];
            Buffer.BlockCopy(data, 0, signedMessage, 0, data.Length);
            Buffer.BlockCopy(ComputeSignature(data), 0, signedMessage, data.Length, hashLength);
            return signedMessage;
        }

        public byte[] StripSignature(byte[] signedMessage)
        {
            int hashLength = _algorithm.HashSize / 8;
            int dataLength = signedMessage.Length - hashLength;
            byte[] data = new byte[dataLength];
            Buffer.BlockCopy(signedMessage, 0, data, 0, data.Length);
            return data;
        }

        public bool Validate(byte[] signedMessage)
        {
            int hashLength = _algorithm.HashSize / 8;
            int dataLength = signedMessage.Length - hashLength;
            return Validate(signedMessage, dataLength);
        }

        private bool Validate(byte[] signedMessage, int dataLength)
        {
            bool isValid = true;
            byte[] validSignature = ComputeSignature(signedMessage, 0, dataLength);
            if (signedMessage.Length != dataLength + validSignature.Length)
            {
                return false;
            }
            for (int i = 0; i < validSignature.Length; i++)
            {
                if (i + dataLength >= signedMessage.Length)
                {
                    isValid = false;
                }
                if (signedMessage[i + dataLength] != validSignature[i])
                {
                    isValid = false;
                }
            }
            return isValid;
        }
    }

    public class SafeCrypt
    {
        private SymmetricEncryption encryption;
        private KeyedHashValidation validation;

        public SafeCrypt(byte[] encryptionKey, byte[] validationKey)
        {
            initAlgorithms(encryptionKey, validationKey);
        }

        // Gets Encryption key and Validation key from AppSettings (Web.config)
        public SafeCrypt(string encryptionKeyString, string validationKeyString)
        {
            // Get the (static) encryption/validation keys and salt from web.config
            byte[] encryptionKey = SoapHexBinary.Parse(encryptionKeyString).Value;
            byte[] validationKey = SoapHexBinary.Parse(validationKeyString).Value;
            initAlgorithms(encryptionKey, validationKey);
        }

        // Encryption key: A key of 256-bit length in the form of a byte array.
        // Validation key: A key of any length in the form of a byte array.
        private void initAlgorithms(byte[] encryptionKey, byte[] validationKey)
        {
            // Rijndael (AES) encryption algorithm
            this.encryption = new SymmetricEncryption(SymmetricAlgorithm.Create("rijndael"), encryptionKey);
            // HMAC-SHA256 validation algorithm
            this.validation = new KeyedHashValidation(KeyedHashAlgorithm.Create("hmacsha256"), validationKey);
        }

        public string Encode(byte[] data)
        {
            data = encryption.Encrypt(data, null);
            data = validation.Sign(data);

            return Convert.ToBase64String(data);
        }

        public byte[] Decode(string data)
        {
            byte[] cookieData = Convert.FromBase64String(data);

            if (!validation.Validate(cookieData))
            {
                return null;
            }

            cookieData = validation.StripSignature(cookieData);
            cookieData = encryption.Decrypt(cookieData, null);

            return cookieData;
        }
    } 
}