<?php
if (!isset($_GET['token'])) { //if no token, redirect
    if (isset($_GET['site'])) {
        header('Location: http://localhost:13627/LoginHandler.ashx?site=' . $_GET['site']);
    } else {
        header('Location: http://localhost:13627/LoginHandler.ashx');
    }
    exit();
}

//hex keys
$encryptionkey_hex = "1AE7AF71D4EB4F382226D3E36441934CBF27DD437720135E287B554BDDDC85A2";
$validationkey_hex = "9FA1F8EA0EA0375E51562E30AEBB78C55A8AC7CE3B15260232D5A7DEDD3B6314";
//Convert hex keys to binary
$encryptionkey_bin = pack('H*', $encryptionkey_hex);
$validationkey_bin = pack('H*', $validationkey_hex);

$encrypted_bin = base64_decode($_GET['token']);

if(validate_signature($encrypted_bin, $validationkey_bin)) { //signatures match
    $decrypted_token = decrypt($encrypted_bin, $encryptionkey_bin);
    //Remove control characters at the end of the token from .NET JSON gen. Regex based on http://stackoverflow.com/questions/1401317/remove-non-utf8-characters-from-string
    $decrypted_token = preg_replace('/[\x00-\x1F\x7F]/', '', $decrypted_token);

    //Handle site redirection
    if (isset($_GET['site'])) {
        echo 'You should be navigated to site: ' . $_GET['site'] . '</br>';
    }
    //Do something with the object
    $json = json_decode($decrypted_token);
    echo 'I received the following JSON object:';
    var_dump($json);
} else {
    echo 'The token was not valid.';
}

function validate_signature($encrypted_data, $validation_key) {
    //The current signature on the token is stored in the last 32 bytes
    $existing_signature = substr($encrypted_data, -32);
    //The signature is based on all the token data (except the signature itself).
    $signed_data = substr($encrypted_data, 0, -32);
    //Calculate own signature
    $signature_out = hash_hmac("sha256", $signed_data, $validation_key, true);
    return strcmp($existing_signature, $signature_out) === 0;
}

function decrypt($encrypted_data, $encryption_key) {
    //Retrieve token data
    $initialization_vector = substr($encrypted_data, 0, 16); //initialization vector is first 16 bytes

    $encrypted_data = substr($encrypted_data, 16, -32); //token data
    return mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $encryption_key, $encrypted_data, MCRYPT_MODE_CBC, $initialization_vector);
}

function encrypt($data, $encryption_key, $validation_key) {
    $iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
    srand(); //seed the random number generator
    $iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);

    $encrypted_data = $iv; //prefix with the ini-vector - 16 bytes
    $encrypted_data .= mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $encryption_key, $data, MCRYPT_MODE_CBC, $iv); //add encrypted data
    $encrypted_data .= hash_hmac("sha256", $encrypted_data, $validation_key, true); //Append signature - 32 bytes
    return $encrypted_data;
}
?>