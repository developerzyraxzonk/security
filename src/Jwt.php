<?php 
namespace Xdevpusaka\Security;

use closure;
use Exception;

class Jwt {

	private $header;
	private $payload;
	private $key;

	public function __construct() {
		
		$this->header 	= [
			'alg' => "HS256",
			'typ' => "JWT"
		];

		$this->payload 	= NULL;
	
	}

	function base64url_encode($data) {

		// First of all you should encode $data to Base64 string
		$b64 = base64_encode($data);

		// Make sure you get a valid result, otherwise, return FALSE, as the base64_encode() function do
		if ($b64 === false) {
		return false;
		}

		// Convert Base64 to Base64URL by replacing “+” with “-” and “/” with “_”
		$url = strtr($b64, '+/', '-_');

		// Remove padding character from the end of line and return the Base64URL result
		return rtrim($url, '=');
	}

	/**
	 * Decode data from Base64URL
	 * @param string $data
	 * @param boolean $strict
	 * @return boolean|string
	 */
	function base64url_decode($data, $strict = false) {

		// Convert Base64URL to Base64 by replacing “-” with “+” and “_” with “/”
		$b64 = strtr($data, '-_', '+/');

		// Decode Base64 string and return the original data
		return base64_decode($b64, $strict);

	}

	public function generate( $key, $payload ) {

		$header 	= json_encode($this->header);		
		$header 	= $this->base64url_encode($header);

		$payload 	= json_encode($payload);
		$payload 	= $this->base64url_encode($payload);

		$signature 	= hash_hmac('sha256', "$header.$payload", $key, true);
		$signature 	= $this->base64url_encode($signature); 

		$token 		= "$header.$payload.$signature";

		return $token;

	}

	public function verify( $key, $token ) {

		$part 		= explode(".", $token);
		
		if( count($part) !== 3 ) {
			return false;
		}

		$header 	= json_encode($this->header);
		$header 	= $this->base64url_encode($header);

		$payload 	= $part[1];		

		$signature 	= hash_hmac('sha256', "$header.$payload", $key, true);
		$signature 	= $this->base64url_encode($signature);

		$gived 		= $part[2];

		if( $signature === $gived ) {

			$this->payload = json_decode(base64_decode($payload));

			return true;
			
		}

		return false;

	}

	public function payload() {
		
		return $this->payload;

	}

}
