<?php

namespace ride\library\security\authenticator\io;

/**
 * Input/output implementation for the authenticator to set variables which
 * are available over multiple requests (session, cookie, ...)
 */
interface AuthenticatorIO {

    /**
     * Sets a value to the storage
     * @param string $key
     * @param string $value
     * @return null
     */
    public function set($key, $value);

    /**
     * Gets a value from the storage
     * @param string $key
     * @param string|null
     */
    public function get($key);

}