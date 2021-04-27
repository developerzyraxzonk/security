<?php 
namespace Xdevpusaka\Security;

use closure;
use Exception;

class Auth {

	static function addRole( $role ) {

		if (session_status() == PHP_SESSION_NONE) {
		    session_start();
		}

		$key = config('xdevpusaka.key');

		$_SESSION[md5('xdevpusakarole')] 	= Crypto::encryptString($key, $role);

	}

	static function role( $match ) {

		if (session_status() == PHP_SESSION_NONE) {
		    session_start();
		}

		if( !isset($_SESSION[md5('xdevpusakarole')]) ) {

			return FALSE;

		}

		$key 	= config('xdevpusaka.key');

		$role 	= $_SESSION[md5('xdevpusakarole')];

		$role 	= Crypto::decryptString($key, $role);

		return ($role === $match);

	}

	static function generateToken( $data ) {

		$key 	= config('xdevpusaka.key');

		$Jwt 	= new Jwt();

		return $Jwt->generate( $key, $data );

	}

	static function payload( $token ) {

		$key 	= config('xdevpusaka.key');

		$Jwt 	= new Jwt();

		if( !$Jwt->verify( $key, $token ) ) {

			return NULL;
		
		}else {

			return $Jwt->payload();

		}

	}

	static function setToken( $token ) {

		if (session_status() == PHP_SESSION_NONE) {
		    session_start();
		}

		$key = config('xdevpusaka.key');

		$_SESSION[md5('xdevpusakatoken')] 	= Crypto::encryptString($key, $token);

	}

	static function user() {

		$token = self::getToken();

		return self::payload($token);

	}

	static function getToken() {

		if (session_status() == PHP_SESSION_NONE) {
		    session_start();
		}

		if( !isset($_SESSION[md5('xdevpusakatoken')]) ) {
			return NULL;
		}

		$key 	= config('xdevpusaka.key');

		$token 	= $_SESSION[md5('xdevpusakatoken')];

		$token 	= Crypto::decryptString($key, $token);

		return $token;

	}

	static function destroy() {

		if (session_status() == PHP_SESSION_NONE) {
		    session_start();
		}

		unset($_SESSION[md5('xdevpusakarole')]);
		unset($_SESSION[md5('xdevpusakatoken')]);

	}

}