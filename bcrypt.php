<?php
/**
 * LightPHP Framework
 * LitePHP is a framework that has been designed to be lite waight, extensible and fast.
 * 
 * @author Robert Pitt <robertpitt1988@gmail.com>
 * @category core
 * @copyright 2013 Robert Pitt
 * @license GPL v3 - GNU Public License v3
 * @version 1.0.0
 */

/**
 * Bcrypt class
 *
 * This class is based on: https://github.com/cosenary/Bcrypt-PHP-Class
 */
class Bcrypt_Library
{
	/**
	 * Work cost factor
	 * range between 04-31
	 * 
	 * @var string
	 */
	private $_workFactor = 8;

	/**
	 * All valid hash identifiers
	 * 
	 * @var array
	 */
	private $_validIdentifiers = array ('2a', '2x', '2y');

	/**
	 * Constructor
	 */
	public function __construct()
	{
		/**
		 * Validate the PHP Version is sufficient.
		 */
		if (version_compare(PHP_VERSION, '5.3') < 0)
		{
			throw new Exception('Bcrypt requires PHP 5.3 or above');
		}

		/**
		 * Validate OpenSSL is installed for php.
		 */
		if (!function_exists('openssl_random_pseudo_bytes'))
		{
			throw new Exception('PHP OpenSSL Library is missing.');
		}
	}

	/**
	 * Hash password
	 * 
	 * @param string $password
	 * @param integer $workFactor
	 * @return string
	 */
	public function encrypt($password, $workFactor = 0, $identifier = '2y')
	{
		/**
		 * Return the hash
		 */
		return crypt($password, $this->_genSalt($workFactor, $identifier));
	}

	/**
	 * Check bcrypt password
	 * 
	 * @param string $password
	 * @param string $storedHash
	 * @return boolean
	 */
	public function validate($password, $storedHash)
	{
		/**
		 * Validate the identifier
		 */
		try {
			$this->_validateIdentifier($storedHash);
		}catch(Exception $e)
		{
			return false;
		}

		/**
		 * Validate
		 */
		return (crypt($password, $storedHash) === $storedHash);
	}

	private function _genSalt($workFactor, $identifier = '2y')
	{
		if ($workFactor < 4 || $workFactor > 31)
		{
			$workFactor = $this->_workFactor;
		}

		/**
		 * Generate some random bytes
		 * @var string
		 */
		$input = $this->_getRandomBytes();

		/**
		 * Begin the salt with hte initial hash identifier
		 * @var string
		 */
		$salt = '$' . $identifier . '$';

		/**
		 * Append the work factor to the hash
		 */
		$salt .= str_pad($workFactor, 2, '0', STR_PAD_LEFT) . '$';

		/**
		 * Return the salt.
		 */
		return $salt . substr(strtr(base64_encode($input), '+', '.'), 0, 22);
	}

	/**
	 * OpenSSL's random generator
	 * 
	 * @return string
	 */
	private function _getRandomBytes()
	{
		return openssl_random_pseudo_bytes(16);
	}

	/**
	 * Validate Identifier
	 * @param  string $hash
	 * @return void
	 */
	private function _validateIdentifier($hash)
	{
		if (!in_array(substr($hash, 1, 2), $this->_validIdentifiers))
		{
			throw new Exception('Unsupported hash format.');
		}
	}
}