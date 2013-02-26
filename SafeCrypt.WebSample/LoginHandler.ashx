﻿<%@ WebHandler Language="C#" Class="TrueHandler" %>

using System;
using System.Web;
using System.Configuration;
using System.Text;
using System.Security.Cryptography;
using SafeCrypt;

/// <summary>
/// Summary description for ValidationHandler
/// </summary>
public class TrueHandler : IHttpHandler
{
    public void ProcessRequest(HttpContext context)
    {
        string baseurl = "http://localhost/safecrypt.php?token=";

        var EncryptionKey = "1AE7AF71D4EB4F382226D3E36441934CBF27DD437720135E287B554BDDDC85A2";
        var ValidationKey = "9FA1F8EA0EA0375E51562E30AEBB78C55A8AC7CE3B15260232D5A7DEDD3B6314";

        //Retrieve and instantiate token JSON object.
        var serializer = new System.Web.Script.Serialization.JavaScriptSerializer();
        string token = serializer.Serialize(new
        {
            login = "tlb",
            name = "Troels Liebe Bentsen",
            email = "test@test.dk"
        });

        //Encode the token
        var sc = new SafeCrypt.SafeCrypt(EncryptionKey, ValidationKey);
        var encodedToken = sc.Encode(Encoding.UTF8.GetBytes(token));
        //Create redirect url
        var redirectUrl = baseurl + HttpUtility.UrlEncode(encodedToken);
        if (context.Request.QueryString["site"] != null)
        {
            var site = context.Request.QueryString["site"];
            redirectUrl += "&site=" + HttpUtility.UrlEncode(site);
        }
        context.Response.Redirect(redirectUrl, false);
    }

    public bool IsReusable
    {
        get
        {
            return false;
        }
    }
}

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
            using (System.IO.MemoryStream output = new System.IO.MemoryStream())
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
            using (System.IO.MemoryStream output = new System.IO.MemoryStream())
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
            byte[] encryptionKey = System.Runtime.Remoting.Metadata.W3cXsd2001.SoapHexBinary.Parse(encryptionKeyString).Value;
            byte[] validationKey = System.Runtime.Remoting.Metadata.W3cXsd2001.SoapHexBinary.Parse(validationKeyString).Value;
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

