<?php

namespace pallo\library\security\exception;

use \Exception;

/**
 * Unauthorized exception
 */
class UnauthorizedException extends SecurityException {

    /**
     * Constructs a unauthorized exception
     * @param string $message The message of the exception
     * @param integer $code Code of the exception
     * @param Exception $previous Previous exception which caused this exception
     * @return null
     */
    public function __construct($message = null, $code = null, Exception $previous = null) {
        if ($code === null) {
            $code = 202;
        }

        parent::__construct($message, $code, $previous);
    }

}