<?php

namespace pallo\library\security\model;

use pallo\library\security\matcher\PathMatcher;

/**
 * User of the SecurityModel
 */
interface User {

    /**
     * Gets the unique id of this user
     * @return string
     */
    public function getId();

    /**
     * Sets the display name of this user
     * @param string $name
     * @return
     */
    public function setDisplayName($name);

    /**
     * Gets the display name of this user
     * @return string
     */
    public function getDisplayName();

    /**
     * Sets the name to identify this user
     * @param string $name The username to identify the user
     * @return null
     */
    public function setUserName($name);

    /**
     * Gets the name to identify this user
     * @return string
     */
    public function getUserName();

    /**
     * Gets the password of this user
     * @return string Encrypted password
     */
    public function getPassword();

    /**
     * Sets a new password for this user
     *
     * This method will run the security.password.update event before setting the password. This event
     * has the User object and the new plain password as arguments.
     * @param string $password Plain text password
     * @return null
     * @see SecurityModel
     */
    public function setPassword($password);

    /**
     * Gets the email address of this user
     * @return string
     */
    public function getEmail();

    /**
     * Sets the email address of this user
     * @param string $email
     * @return
     */
    public function setEmail($email);

    /**
     * Gets whether this user is active
     * @return boolean
     */
    public function isActive();

    /**
     * Sets whether this user is active
     * @param boolean $flag
     * @return null
     */
    public function setIsActive($flag);

    /**
     * Checks whether this user is a super user and thus can perform everything
     * @return @boolean True if this user is a super user, false otherwise
     */
    public function isSuperUser();

    /**
     * Sets whether this user is a super user
     * @param boolean $flag
     * @return null
     */
    public function setIsSuperUser($flag);

    /**
     * Checks whether a permission is granted for this user
     * @param string $code Code of the permission to check
     * @return boolean True if permission is granted, false otherwise
     * @see SecurityManager::ASTERIX
     */
    public function isPermissionGranted($code);

    /**
     * Checks whether a path is allowed for this user
     * @param string $path Path to check
     * @param pallo\library\security\matcher\PathMatcher $pathMatcher To match
     * path regular expression on the route
     * @return boolean True if the path is allowed, false otherwise
     */
    public function isPathAllowed($path, PathMatcher $pathMatcher);

    /**
     * Gets the roles of this user
     * @return array Array of Role objects
     */
    public function getRoles();

    /**
     * Gets all the preferences of this user
     * @return array Array with the name of the setting as key and the setting as value
     */
    public function getPreferences();

    /**
     * Gets a preference of this user
     * @param string $name Name of the preference
     * @param mixed $default Default value for when the preference is not set
     * @return mixed The value of the preference or the provided default value if the preference is not set
     */
    public function getPreference($name, $default = null);

    /**
     * Sets a preference for this user
     * @param string $name Name of the preference
     * @param mixed $value Value for the preference
     * @return null
     */
    public function setPreference($name, $value);

}