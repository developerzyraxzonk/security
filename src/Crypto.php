<?php 
namespace Xdevpusaka\Security;

use closure;
use Exception;

class Crypto {

	const ALGORITHM = 'AES-256-CBC';

	static function base64UrlEncode( $data ) {

		$b64 = base64_encode($data);

		if ($b64 === false) {
			return false;
		}

		$url = strtr($b64, '+/', '-_');

		return rtrim($url, '=');

	}

	static function base64UrlDecode( $data, $strict = false ) {

		// Convert Base64URL to Base64 by replacing “-” with “+” and “_” with “/”
		$b64 = strtr($data, '-_', '+/');

		// Decode Base64 string and return the original data
		return base64_decode($b64, $strict);

	}

	static function encryptString($key, $data) {

		$cipher 	= self::ALGORITHM;

		$ivlen 		= openssl_cipher_iv_length($cipher);
		$iv 		= openssl_random_pseudo_bytes($ivlen);

		$encoded 	= openssl_encrypt($data, $cipher, $key, $options=0, $iv);

		$iv 		= self::base64UrlEncode($iv);

		$encoded 	= self::base64UrlEncode($encoded);

		$signature 	= hash_hmac('sha256', $iv.$encoded, $key, true);

		$encrypt 	= $iv . '.' . $encoded . '.' . self::base64UrlEncode($signature);

		return $encrypt;

	}

	static function decryptString($key, $data) {

		$cipher 	= self::ALGORITHM;

		$token 		= explode('.', $data);

		if(count($token) !== 3 ) {
			throw new Exception('Format data invalid.');
		}

		list($iv, $encoded, $signature) = $token;

		$signature 	= self::base64UrlDecode($signature);

		$confirm 	= hash_hmac('sha256', $iv.$encoded, $key, true);

		if(!hash_equals($signature, $confirm)) {
			throw new Exception('Invalid hash token.');
		}

		$iv 		= self::base64UrlDecode($iv);

		$encoded 	= self::base64UrlDecode($encoded);

		$decoded 	= openssl_decrypt($encoded, $cipher, $key, $options=0, $iv);

		return $decoded;

	}

}