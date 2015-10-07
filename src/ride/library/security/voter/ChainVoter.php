<?php

namespace ride\library\security\voter;

use ride\library\security\exception\SecurityException;
use ride\library\security\model\User;
use ride\library\security\SecurityManager;

/**
 * Chain of voters to implement your security layer
 */
class ChainVoter extends AbstractVoter {

    /**
     * Strategy which grants access as soon as one voter grants access
     * @var string
     */
    const STRATEGY_AFFIRMATIVE = 'affirmative';

    /**
     * Strategy which grants access when more voters grant access instead of
     * denying access
     * @var string
     */
    const STRATEGY_CONSENSUS = 'consensus';

    /**
     * Strategy which grants access when all voters grant access
     * @var string
     */
    const STRATEGY_UNANIMOUS = 'unanimous';

    /**
     * Strategy of this chain
     * @var string
     */
    private $strategy;

    /**
     * Voters of the chain
     * @var array
     * @see Voter
     */
    private $voters;

    /**
     * Constructs a new voter chain
     * @param string $strategy Strategy of the chain
     * @return null
     */
    public function __construct($strategy = null) {
        if ($strategy === null) {
            $strategy = self::STRATEGY_AFFIRMATIVE;
        }

        $this->setStrategy($strategy);

        $this->voters = array();
    }

    /**
     * Sets the security manager to the authenticator
     * @param \ride\library\security\SecurityManager $securityManager Instance
     * of the security manager
     * @return null
     */
    public function setSecurityManager(SecurityManager $securityManager = null) {
        $this->securityManager = $securityManager;

        foreach ($this->voters as $voter) {
            $voter->setSecurityManager($securityManager);
        }
    }

    /**
     * Sets the strategy of this voter
     * @param string $strategy One of the strategy constants (affirmative,
     * consensus or unanimous)
     * @return null
     * @throw \ride\library\security\exception\SecurityException when an invalid
     * strategy is provided
     */
    public function setStrategy($strategy) {
        if ($strategy !== self::STRATEGY_AFFIRMATIVE && $strategy !== self::STRATEGY_CONSENSUS && $strategy !== self::STRATEGY_UNANIMOUS) {
            throw new SecurityException('Could not set the strategy of this chain: invalid strategy provided, try affirmative, consensus or unanimous');
        }

        $this->strategy = $strategy;
    }

    /**
     * Gets the strategy of this chain
     * @return null
     */
    public function getStrategy() {
        return $this->strategy;
    }

    /**
     * Adds a voter to the chain
     * @param Voter $voter Voter to add
     * @param boolean $prepend Set to true to add to the beginning of the chain
     * @return boolean True if added, false if this voter was already added
     */
    public function addVoter(Voter $voter, $prepend = false) {
        foreach ($this->voters as $i => $v) {
            if ($voter === $v) {
                return false;
            }
        }

        $this->voters[] = $voter;

        $voter->setSecurityManager($this->securityManager);

        return true;
    }

    /**
     * Adds multiple voters to the chain
     * @param array $voters Array of voters
     * @return null
     * @see Voter
     */
    public function addVoters(array $voters) {
        foreach ($voters as $index => $voter) {
            if (!$voter instanceof Voter) {
                throw new SecurityException('Could not add voters: value at index ' . $index . ' is not an instance of ride\\library\\security\\voter\\Voter');
            }

            $this->addVoter($voter);
        }
    }

    /**
     * Removes a voter from the chain
     * @param Voter $voter Voter to remove
     * @return boolean True if removed, false if not found
     */
    public function removeVoter(Voter $voter) {
        foreach ($this->voters as $i => $v) {
            if ($voter === $v) {
                unset($this->voters[$i]);

                return true;
            }
        }

        return false;
    }

    /**
     * Checks if the provided permission is granten by the provided user
     * @param string $permission Code of the permission to check
     * @param \ride\library\security\model\User $user User to check
     * @return boolean|null True when granted, false when not granted or null
     * when this voter has no opinion
     */
    public function isGranted($permission, User $user = null) {
        if (!$this->voters) {
            // no voters, no opinion
            return null;
        }

        $result = array();

        foreach ($this->voters as $i => $voter) {
            $result[$i] = $voter->isGranted($permission, $user);

            if ($this->strategy === self::STRATEGY_AFFIRMATIVE && $result[$i]) {
                // affirmative and granted by the voter, we grant the permission
                return true;
            }
        }

        return $this->applyStrategy($result);
    }

    /**
     * Checks if the provided path is granted by the provided user
     * @param string $path Path to check
     * @param string $method Request method to check
     * @param \ride\library\security\model\User $user User to check
     * @return boolean|null True when allowed, false when not allowed or null
     * when this voter has no opinion
     */
    public function isAllowed($path, $method = null, User $user = null) {
        if (!$this->voters) {
            // no voters, no opinion
            return null;
        }

        $result = array();

        foreach ($this->voters as $i => $voter) {
            $result[$i] = $voter->isAllowed($path, $method, $user);

            if ($this->strategy === self::STRATEGY_AFFIRMATIVE && $result[$i]) {
                // affirmative and allowed by the voter, we allow the path
                return true;
            }
        }

        return $this->applyStrategy($result);
    }

    /**
     * Applies the strategy on the provided result
     * @param array $result Array with the results of the voters
     * @return boolean
     */
    private function applyStrategy(array $result) {
        if ($this->strategy === self::STRATEGY_CONSENSUS) {
            $numGranted = 0;
            $numDenied = 0;

            foreach ($result as $isGranted) {
                if ($isGranted === true) {
                    $numGranted++;
                } elseif ($isGranted === false) {
                    $numDenied++;
                }
            }

            if ($numGranted > $numDenied) {
                // more voters granted instead of denying, we grant the permission
                return true;
            }
        } elseif ($this->strategy === self::STRATEGY_UNANIMOUS) {
            // unanimous so all voters should grant
            foreach ($result as $isGranted) {
                if (!$isGranted) {
                    // denied by voters, we deny the permission
                    return false;
                }
            }

            // granted by all voters, we grant the permission
            return true;
        }

        // denied if no grant came out
        return false;
    }

}
