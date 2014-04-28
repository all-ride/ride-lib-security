<?php

namespace ride\library\security\model;

/**
 * Model of the security data
 */
interface SecurityModel {

    /**
     * Checks if the security model is ready to work
     * @return boolean True if the model is ready, false otherwise
     */
    public function ping();

    /**
     * Gets the paths which are secured for anonymous users
     * @return array Array with a path regular expression per element
     */
    public function getSecuredPaths();

    /**
     * Sets the paths which are secured for anonymous users
     * @param array $routes Array with a path regular expression per element
     * @return null
     */
    public function setSecuredPaths(array $paths);

    /**
     * Sets the granted permissions to a role
     * @param Role $role Role to set the permissions to
     * @param array $permissionCodes Array with a permission code per element
     * @return null
     */
    public function setGrantedPermissionsToRole(Role $role, array $permissionCodes);

    /**
     * Sets the allowed paths to a role
     * @param Role $role Role to set the routes to
     * @param array $paths Array with a path regular expression per element
     * @return null
     */
    public function setAllowedPathsToRole(Role $role, array $paths);

    /**
     * Saves the provided roles for the provided user
     * @param User $user User to update
     * @param array $roles The roles to set to the user
     * @return null
     */
    public function setRolesToUser(User $user, array $roles);

    /**
     * Gets a user by it's id
     * @param string $id Id of the user
     * @return User|null User object if found, null otherwise
     */
    public function getUserById($id);

    /**
     * Gets a user by it's username
     * @param string $username Username of the user
     * @return User|null User object if found, null otherwise
     */
    public function getUserByUsername($username);

    /**
     * Gets a user by it's email address
     * @param string $email Email address of the user
     * @return User|null User object if found, null otherwise
     */
    public function getUserByEmail($email);

    /**
     * Gets the users
     * @param array $options Extra options for the query
     * <ul>
     *     <li>query</li>
     *     <li>name</li>
     *     <li>username</li>
     *     <li>email</li>
     *     <li>page</li>
     *     <li>limit</li>
     * </ul>
     * @return array
     */
    public function getUsers(array $options = null);

    /**
     * Counts the users
     * @param array $options Extra options for the query
     * <ul>
     *     <li>query</li>
     *     <li>name</li>
     *     <li>username</li>
     *     <li>email</li>
     * </ul>
     * @return integer
     */
    public function countUsers(array $options = null);

    /**
     * Creates a new user
     * @return User
     */
    public function createUser();

    /**
     * Saves a user to the model
     * @param User $user User to save
     * @return null
     */
    public function saveUser(User $user);

    /**
     * Deletes the provided user
     * @param User $user User to delete
     * @return null
     */
    public function deleteUser(User $user);

    /**
     * Gets a role by it's id
     * @param string $id Id of the role
     * @return Role|null Role object if found, null otherwise
     */
    public function getRoleById($id);

    /**
     * Gets a role by it's name
     * @param string $name Name of the role
     * @return Role|null Role object if found, null otherwise
     */
    public function getRoleByName($name);

    /**
     * Gets all the roles
     * @param array $options Extra options for the query
     * <ul>
     *     <li>name</li>
     *     <li>query</li>
     *     <li>page</li>
     *     <li>limit</li>
     * </ul>
     * @return array
     */
    public function getRoles(array $options = null);

    /**
     * Counts the roles
     * @param array $options Extra options for the query
     * <ul>
     *     <li>query</li>
     *     <li>name</li>
     * </ul>
     * @return integer
     */
    public function countRoles(array $options = null);

    /**
     * Creates a new role
     * @return Role
     */
    public function createRole();

    /**
     * Saves a role to the model
     * @param Role $role Role to save
     * @return null
     */
    public function saveRole(Role $role);

    /**
     * Deletes a role from the model
     * @param Role $role
     * @return null
     */
    public function deleteRole(Role $role);

    /**
     * Gets all the permissions
     * @return array Array with Permission objects
     */
    public function getPermissions();

    /**
     * Checks whether a given permission is available
     * @param string $code Code of the permission to check
     * @return boolean
     */
    public function hasPermission($code);

    /**
     * Registers a new permission to the model
     * @param string $code Code of the permission
     * @return null
     */
    public function addPermission($code);

    /**
     * Unregisters an existing permission from the model
     * @param string $code Code of the permission
     * @return null
     */
    public function deletePermission($code);

}
