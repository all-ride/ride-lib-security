# Ride: Security Library

Security abstraction library of the PHP Ride framework.

This library implements a role-based access control.
Read more about this on [Wikipedia](https://en.wikipedia.org/wiki/Role-based_access_control).

## What's In This Library

### SecurityModel

The _SecurityModel_ interface is the facade to the data source of the security implementation.
It provides users, roles and permissions.

#### User

The _User_ interface represents a user which can identify him or herself to the application.
You can attach roles to the user to grant him or her access to specific parts of the application.
The _User_ interface is implemented by the security model.

#### Role

The _Role_ interface represents a specific set of allowed actions through granted permissions and allowed paths.
By attaching a role to a user, you grant the user access to specific parts of the application.
The _Role_ interface is implemented by the security model.

#### Permission

The _Permission_ interface is used to grant or deny a single action.

To secure a part of your application, you should always check for a granted permission in the application code.
Don't check if the current user is a specific user, or if the current user has a specific role.
You will work against the flexibility of the security model.

The _Permission_ interface is implemented by the security model.

### Authenticator

The _Authenticator_ interface decides the mechanism of authentication and keeps the state of the current user.

#### GenericAuthenticator

The _GenericAuthenticator_ offers a default or generic implementation of the authenticator.

You can turn on unique sessions.
This feature is used when a user performs a login from another client, the original client will be logged out.

It also supports the switch user functionality.

#### ChainAuthenticator

You can use the _ChainAuthenticator_ to chain different authenticators together.
Use this to offer different authentication mechanisms simultaneously.

### PathMatcher

The _PathMatcher_ has the responsibility to match path regular expressions, or rules, to a provided path and method.

#### GenericPathMatcher

The _GenericPathMatcher_ offers a default or generic implementation of the path matcher.

There are 3 special tokens which you can use in a rule:
* __*__: match a single path token
* __**__: match everything
* __!__: prefix a path with an exclamation mark to negative (not) it

Optionally, you can define one or multiple methods between square brackets.

All rules will be checked and it will happen in the sequence they are provided.
This is needed for the not function. 

For example, assume the following rules:

```
/admin**
/sites**
!/sites/my-site/pages/*/content [GET]
```

These rules will match all requests starting with _/admin_ and _/sites_ except a GET request for the content of every page of _my-site_. 

### Voter

The _Voter_ interface is used to check granted permissions and allowed paths.

#### ModelVoter

The _ModelVoter_ performs it's checks against the security model.
It uses the current user and it's roles to obtain granted permissions and allowed paths.

#### ChainVoter

The _ChainVoter_ is used to combine different voters in a chain.
This can be used to catch special cases or some exotic edge case.

You have 3 different strategies:
* __affirmative__: This strategy grants access as soon as one voter grants access. This is the default strategy.
* __consensus__: This strategy grants access when there is a majority of voters who grant access.
* __unanimous__: This strategy grants access when all voters grant access.

### SecurityManager

The _SecurityManager_ class is the facade to this library.
It glues the other components together to an easy to use interface.
Use an instance of this class to handle your security.

## Code Sample

Check this code sample to see some possibilities of this library:

_Note: some classes used in this example are taken from from [ride/lib-security-generic](https://github.com/all-ride/ride-lib-security-generic), [ride/web-security](https://github.com/all-ride/ride-web-security) or [ride/web-security-generic](https://github.com/all-ride/ride-web-security-generic).

```php
<?php

use ride\library\encryption\hash\GenericHash;
use ride\library\event\EventManager;
use ride\library\http\Request;
use ride\library\security\authenticator\ChainAuthenticator;
use ride\library\security\authenticator\GenericAuthenticator;
use ride\library\security\exception\EmailAuthenticationException;
use ride\library\security\exception\InactiveAuthenticationException;
use ride\library\security\exception\PasswordAuthenticationException;
use ride\library\security\exception\UnauthorizedException;
use ride\library\security\exception\UsernameAuthenticationException;
use ride\library\security\exception\UserNotFoundException;
use ride\library\security\exception\UserSwitchException;
use ride\library\security\matcher\GenericPathMatcher;
use ride\library\security\model\generic\GenericSecurityModel;
use ride\library\security\model\ChainSecurityModel;
use ride\library\security\voter\ChainVoter;
use ride\library\security\voter\ModelVoter;
use ride\library\security\SecurityManager;
use ride\library\system\file\File;

use ride\web\security\authenticator\io\SessionAuthenticatorIO;
use ride\web\security\authenticator\HttpAuthenticator;

function createSecurityManager(EventManager $eventManager, File $fileSecurityModel) {
    // first create the default authenticator
    $sessionAuthenticatorIO = new SessionAuthenticatorIO(); // used to store values in the session
    $salt = 'a-random-string'; // salt for value generation
    $timeout = 1800; // time in seconds
    $isUnique = false; // allow only 1 client per user at the same time
    
    $genericAuthenticator = new GenericAuthenticator($sessionAuthenticatorIO, $salt, $timeout, $isUnique);
    
    // we use a chain so we can add other implementations like HTTP authentication or OAuth
    $chainAuthenticator = new ChainAuthenticator();
    $chainAuthenticator->addAuthenticator($genericAuthenticator);
    
    // let's add the HTTP authenticator to the chain (optional)
    $realm = 'My Site'; // the title of the login box
    $httpAuthenticator = new HttpAuthenticator($sessionAuthenticatorIO, $realm, $eventManager);
    
    $chainAuthenticator->addAuthenticator($httpAuthenticator);
    
    // decide the hash algorithm
    $hashAlgorithm = new GenericHash('sha512');
    
    // initialize the voter
    $genericPathMatcher = new GenericPathMatcher();
    
    $modelVoter = new ModelVoter($genericPathMatcher);
    
    // again a chain to add other voters if needed
    $chainVoter = new ChainVoter();
    $chainVoter->addVoter($modelVoter);
    
    // now, we create the security model
    $xmlSecurityModelIO = new XmlSecurityModelIO($fileSecurityModel);
    $genericSecurityModel = new GenericSecurityModel($xmlSecurityModelIO, $eventManager, $hashAlgorithm);
    
    // a chain, you guessed it ...
    $chainSecurityModel = new ChainSecurityModel();
    $chainSecurityModel->addSecurityModel($genericSecurityModel);
    
    // throw it all together in the security manager
    $securityManager = new SecurityManager($chainAuthenticator, $eventManager);
    $securityManager->setHashAlgorithm($hashAlgorithm);
    $securityManager->setSecurityModel($chainSecurityModel);
    $securityManager->setVoter($chainVoter);
    
    return $securityManager;
}

function manageSecurityModel(SecurityManager $securityManager) {
    $securityModel = $securityManager->getSecurityModel();
    
    // set the globally secured paths 
    $securedPaths = array(
        '/admin**',
        '/sites**',
    );
    
    $securityModel->setSecuredPaths($securedPaths);
    
    // create some roles
    $administratorRole = $securityModel->createRole();
    $administratorRole->setName('Administrator');
    $administratorRole->setWeight(99);
    
    $contentManagerRole = $securityModel->createRole();
    $contentManagerRole->setName('Content Manager');
    $contentManagerRole->setWeight(50);
    
    $securityModel->saveRole($adminstratorRole);
    $securityModel->saveRole($contentManagerRole);
    
    // allow paths and grant permissions for the roles
    $securityModel->setAllowedPathsToRole($administratorRole, array('**'));
    $securityModel->setAllowedPathsToRole($contentManagerRole, array('/sites**'));
    
    $securityModel->setGrantedPermissionsToRole($administratorRole, array('security.switch'));
    $securityModel->setGrantedPermissionsToRole($contentManagerRole, array('security.switch'));
    
    // create users
    $administratorUser = $securityModel->createUser();
    $administratorUser->setUsername('admin');
    $administratorUser->setPassword('secure password');
    $administratorUser->setIsActive(true);
    
    $contentManagerUser = $securityModel->createUser();
    $contentManagerUser->setUsername('cm');
    $contentManagerUser->setPassword('secure password');
    $contentManagerUser->setIsActive(true);
    
    $securityModel->saveUser($administratorUser);
    $securityModel->saveUser($contentManagerUser);
    
    // assign roles to the users
    $securityModel->setRolesToUser($administratorUser, array($administratorRole));
    $securityModel->setRolesToUser($contentManagerUser, array($contentManagerRole));
    
    // create a super user
    $superUser = $securityModel->createUser();
    $superUser->setUsername('root');
    $superUser->setPassword('secure password');
    $superUser->setIsActive(true);
    $superUser->setIsSuperUser(true);
    
    $securityModel->saveUser($superUser);
    
    // create a regular user with all properties
    $regularUser = $securityModel->createUser();
    $regularUser->setDisplayName('John Doe');
    $regularUser->setUsername('john');
    $regularUser->setPassword('secure password');
    $regularUser->setEmail('john@doe.com');
    $regularUser->setIsEmailConfirmed(true);
    $regularUser->setImage('upload/users/john-doe-avatar.png');
    $regularUser->setPreference('locale', 'en_GB'); // any custom preference
    $regularUser->setIsActive(true);
    
    $securityModel->saveUser($regularUser);
    
    // delete it again
    $securityModel->deleteUser($regularUser);
    
    // find some users
    $user = $securityModel->getUserById(1);
    $user = $securityModel->getUserByUsername('admin');
    $user = $securityModel->getUserByEmail('john@doe.com');
    
    $options = array(
        // 'query' => 'adm',
        // 'username' => 'adm',
        // 'email' => 'adm',
        'page' => 1,
        'limit' => 20,
    ); 
    
    $users = $securityModel->getUsers($options);
    $numUsers = $securityModel->countUsers($options);
    
    // the same for roles
    $role = $securityModel->getRoleById(1);
    $role = $securityModel->getRoleByName('Content Manager');
    
    $options = array(
        // 'query' => 'content',
        // 'name' => 'content',
        'page' => 1,
        'limit' => 20,
    ); 
    
    $roles = $securityModel->getRoles($options);
    $numRoles = $securityModel->countRoles($options);
    
    // obtain all permissions
    $permissions = $securityModel->getPermissions();
}

function handleSecurity(SecurityManager $securityManager, Request $request) {
    // set the request to the security manager to detect logged in user from previous requests
    $securityManager->setRequest($request);
    
    // get the current user
    $user = $securityManager->getUser();
    if (!$user) {
        // no user logged in from a previous request
        try {
            $securityManager->login('admin', 'secure password');
        } catch (UsernameAuthenticationException $exception) {
            // invalid username
        } catch (PasswordAuthenticationException $exception) {
            // invalid password
        } catch (EmailAuthenticationException $exception) {
            // email is not confirmed
        } catch (InactiveAuthenticationException $exception) {
            // user is inactive
        }
    }
    
    // perform some checks
    if ($securityManager->isPermissionGranted('my.permission')) {
        // user is granted
    } else {
        // user is denied
    }
    
    if ($securityManager->isPathAllowed('/admin/system', 'GET')) {
        // user is allowed
    } else {
        // user is denied
    }
    
    if ($securityManager->isUrlAllowed('https://www.foo.bar/admin/system')) {
        // user is allowed
    } else {
        // user is denied
    }
    
    // mock an other user through the switch user feature
    try {
        $securityManager->switchUser('cm');

        // perform a check on the switched user
        if ($securityManager->isPermissionGranted('my.permission')) {
            // switched user is granted
        } else {
            // switched user is denied
        }
        
        // logout the switched user
        $securityManager->logout();
    } catch (UserNotFoundException $exception) {
        // requested user does not exist
    } catch (UserSwitchException $exception) {
        // can't switch to a super user as a non super user
    } catch (UnauthorizedException $exception) {
        // not allowed to switch user
    }
    
    // logout the current user
    $securityManager->logout();
}
```

### Implementations

For more examples, you can check the following implementations of this library:
- [ride/cli-security](https://github.com/all-ride/ride-cli-security)
- [ride/lib-security-generic](https://github.com/all-ride/ride-lib-security-generic)
- [ride/lib-security-oauth](https://github.com/all-ride/ride-lib-security-oauth)
- [ride/web-security](https://github.com/all-ride/ride-web-security)
- [ride/web-security-generic](https://github.com/all-ride/ride-web-security-generic)
- [ride/web-security-oauth](https://github.com/all-ride/ride-web-security-oauth)
- [ride/web-security-orm](https://github.com/all-ride/ride-web-security-orm)

## Installation

You can use [Composer](http://getcomposer.org) to install this library.

```
composer require ride/lib-security
```
