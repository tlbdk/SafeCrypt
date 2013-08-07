<?php


class safecrypt
{
    private $encryption_key;
    private $validation_key;

    /**
     * Instantiates the class and sets the encryption and validation keys to be used.
     * @param $encryption_key
     * @param $validation_key
     */
    function safecrypt ($encryption_key, $validation_key) {
        $this->encryption_key = $encryption_key;
        $this->validation_key = $validation_key;
    }

    /**
     * Validates the encrypted datas signature and returns true if it passes.
     * @param $encrypted_data The encrypted data to validate
     * @return bool A boolean representing whether or not the validation passed
     */
    function is_valid($encrypted_data) {
        //The current signature on the token is stored in the last 32 bytes
        $existing_signature = substr($encrypted_data, -32);
        //The signature is based on all the token data (except the signature itself).
        $signed_data = substr($encrypted_data, 0, -32);
        //Calculate own signature
        $signature_out = hash_hmac("sha256", $signed_data, $this->validation_key, true);
        return strcmp($existing_signature, $signature_out) === 0;
    }

    /**
     * Decrypts encrypted data
     * @param $encrypted_data The data to decrypt
     * @return string The decrypted data
     */
    function decrypt($encrypted_data) {
        //Retrieve token data
        $initialization_vector = substr($encrypted_data, 0, 16); //initialization vector is first 16 bytes

        $encrypted_data = substr($encrypted_data, 16, -32); //token data

        $decrypted_data = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $this->encryption_key, $encrypted_data, MCRYPT_MODE_CBC, $initialization_vector);

		//Remove the PKCS #7 padding
        $padding_length = ord($decrypted_data[strlen($decrypted_data)-1]);
        return substr($decrypted_data, 0, -$padding_length);
    }

    /**
     * Encrypts data
     * @param $data The data to encrypt
     * @return string The encrypted data
     */
    function encrypt($data) {
        $iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
        srand(); //seed the random number generator
        $iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
		
        //Pad the data to make it interoperable with PKCS #7
        $block_size = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
        $pad = $block_size - (strlen($data) % $block_size);
        $data .= str_repeat(chr($pad), $pad);

        $encrypted_data = $iv; //prefix with the ini-vector - 16 bytes
        $encrypted_data .= mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $this->encryption_key, $data, MCRYPT_MODE_CBC, $iv); //add encrypted data
        $encrypted_data .= hash_hmac("sha256", $encrypted_data, $this->validation_key, true); //Append signature - 32 bytes
        return $encrypted_data;
    }
}
?>