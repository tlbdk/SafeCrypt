SafeCrypt
=========

Cleaned up version of [AppHarbor.Web.Security](https://github.com/appharbor/AppHarbor.Web.Security)
that can be used for anything not just encrypting cookies. We provide an implementation in PHP and C#.

# How to Use #

Drop SafeCrypt.cs and SafeCrypt.php into your project.

C#:

    var EncryptionKey = "...";
    var ValidationKey = "...";
    
    var token = "tlb,Troels Liebe Bentsen";
    var sc = new SafeCrypt(EncryptionKey, ValidationKey);
    var ectoken = sc.Encode(Encoding.UTF8.GetBytes(token));
    Console.WriteLine(ectoken);
    Console.WriteLine(Encoding.UTF8.GetString(sc.Decode(ectoken)));

PHP:

    //hex keys
    $encryptionkey = "...";
    $validationkey = "...";
    
    //Convert hex keys to binary
    $encryptionkeybin = pack('H*', $encryptionkeyhex);
    $validationkeybin = pack('H*', $validationkeyhex);
    
    $encrypted = encrypt($data, $encryptionkeybin, $validationkeybin);
    $decrypted = decrypt($data, $encryptionkeybin, $validationkeybin);

# Security #

This implementation uses Rijndael (AES) algorithm to encrypt the data, and then
sign the encrypted data with HMAC-SHA256. This Encrypt-then-Sign scheme is 
recommended by well-known cryptographers, Mihir Bellare and Chanathip 
Namprempre, in their paper [Authenticated Encryption: Relations among notions 
and analysis of the generic composition paradigm](http://charlotte.ucsd.edu/~mihir/papers/oem.pdf).
Given secure underlying encryption and signing algorithms, this scheme is deemed
secure and is not known to be vulnerable to [Padding Oracle Attacks, like the
one ASP.NET v4.0 forms authentication sufferred from recently](http://netifera.com/research/poet/ieee-aspnetcrypto.pdf).

The other advantage of this solution relative to the ASP.NET's built-in
offering is that ASP.NET reuses the same set of keys that it uses for
forms authentication in other places like ViewState encryption with
varying levels of criticality.  This solution lets you use a unique set
of keys just for authentication.

# TODO #

Implement Java version : http://blog.palominolabs.com/2013/02/12/encryption-in-java/

