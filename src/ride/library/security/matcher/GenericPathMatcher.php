<?php

namespace ride\library\security\matcher;

/**
 * Matcher for a route against route regular expressions
 */
class GenericPathMatcher implements PathMatcher {

    /**
     * Checks if the provided path matches one of the provided path regular
     * expressions
     * @param string $path Path the match
     * @param string $method Request method to check
     * @param array $pathRules Array with path rules
     * @return boolean True if matched, false otherwise
     */
    public function matchPath($path, $method, array $pathRules) {
        // normalize the incoming method
        if ($method === null) {
            $method = 'GET';
        } else {
            strtoupper($method);
        }

        $result = false;

        foreach ($pathRules as $pathRule) {
            $allowedMethods = array();

            $this->extractData($pathRule, $pathRegex, $allowedMethods, $isNot);

            $isMethodAllowed = !($allowedMethods && !isset($allowedMethods[$method]));

            $positionAsterix = strpos($pathRegex, self::ASTERIX);
            if ($positionAsterix === false) {
                // no regular expression characters, use regular comparisson
                if ($path === $pathRegex) {
                    $result = $isNot ? false : true;
                    if (!$isMethodAllowed) {
                        $result = !$result;
                    }
                }

                continue;
            }

            $lengthPathRegex = strlen($pathRegex);
            $hasEndAsterix = $positionAsterix === $lengthPathRegex - 2 && $pathRegex[$lengthPathRegex - 1] == self::ASTERIX;

            // match everything beginning with a string, use regular string comparisson
            if (strncmp($pathRegex, $path, $positionAsterix) === 0) {
                if ($hasEndAsterix) {
                    $result = $isNot ? false : true;
                    if (!$isMethodAllowed) {
                        $result = !$result;
                    }

                    continue;
                }
            } else {
                continue;
            }

            // use regular expression matching
            $regex = str_replace(PathMatcher::ASTERIX . PathMatcher::ASTERIX, '||||||', $pathRegex);
            $regex = str_replace(PathMatcher::ASTERIX, '|||', $regex);
            $regex = str_replace('||||||', '([\w|\W])*', $regex);
            $regex = str_replace('|||', '([^/])*', $regex);
            $regex = str_replace('/', '\\/', $regex);
            $regex = '/^' . $regex . '$/';

            if (preg_match($regex, $path)) {
                $result = $isNot ? false : true;
                if (!$isMethodAllowed) {
                    $result = !$result;
                }
            }
        }

        return $result;
    }

    /**
     * Extracts the path regex and the allowed methods from the path rule
     * @param string $pathRule
     * @param string $pathRegex
     * @param array $allowedMethods
     * @param boolean $isNot
     * @return null
     */
    private function extractData($pathRule, &$pathRegex = null, array &$allowedMethods = array(), &$isNot = false) {
        $isNot = false;
        if (strpos($pathRule, '!') === 0) {
            $isNot = true;
            $pathRule = substr($pathRule, 1);
        }

        $posOpen = strpos($pathRule, '[');
        $posClose = strpos($pathRule, ']');

        if ($posOpen === false || $posClose === false || $posClose < $posOpen) {
            $pathRegex = $pathRule;

            return;
        }

        $pathRegex = trim(substr($pathRule, 0, $posOpen));

        $methods = substr($pathRule, $posOpen + 1, $posClose - $posOpen - 1);
        $methods = strtoupper($methods);

        if ($methods) {
            $allowedMethods = explode(',', $methods);
            $allowedMethods = array_flip($allowedMethods);
        }

    }

}
