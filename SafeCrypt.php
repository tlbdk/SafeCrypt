<?php

$encryptionkey_hex = "1AE7AF71D4EB4F382226D3E36441934CBF27DD437720135E287B554BDDDC85A2";
$validationkey_hex = "9FA1F8EA0EA0375E51562E30AEBB78C55A8AC7CE3B15260232D5A7DEDD3B6314";

$encrypted_base64 = $_GET['token'];

$encryptionkey_bin = pack('H*', $encryptionkey_hex);
$validationkey_bin = pack('H*', $validationkey_hex);

$encrypted_bin = base64_decode($encrypted_base64);

$signature_data = substr($encrypted_bin, 0, -32);
$signature_bin = substr($encrypted_bin, -32);

$signature_out = hash_hmac("sha256", $signature_data, $validationkey_bin, true);

if(strcmp($signature_bin, $signature_out) === 0) {
  $iv_bin = substr($encrypted_bin, 0, 16);
  $encrypted_bin = substr($encrypted_bin, 16, -32);
  $decrypted = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $encryptionkey_bin, $encrypted_bin, MCRYPT_MODE_CBC, $iv_bin);
  echo $decrypted;
}
