<?php

namespace ride\library\security\model;

/**
 * Role of the SecurityModel
 */
interface Role {

    /**
     * Gets the id of this role
     * @return integer
     */
    public function getId();

    /**
     * Sets the name of this role
     * @param string $name
     * @return null
     */
    public function setName($name);

    /**
     * Gets the name of this role
     * @return string
     */
    public function getName();

    /**
     * Sets the weight of this role
     * @param integer $weight
     * @return null
     */
    public function setWeight($weight);

    /**
     * Gets the weight of this role
     * @return integer
     */
    public function getWeight();

    /**
     * Gets the allowed paths of this role
     * @return array Array with a path regular expression per element
     */
    public function getPaths();

    /**
     * Gets the permissions of this role
     * @return array Array with Permission objects
     */
    public function getPermissions();

    /**
     * Checks whether a permission is granted for this role
     * @param string $code Code of the permission to check
     * @return boolean True if permission is granted, false otherwise
     */
    public function isPermissionGranted($code);

}
