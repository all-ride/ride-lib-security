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
     * @param array $pathRegexes Array with path regular expressions
     * @return boolean True if matched, false otherwise
     */
    public function matchPath($path, array $pathRegexes) {
        foreach ($pathRegexes as $pathRegex) {
            $positionAsterix = strpos($pathRegex, self::ASTERIX);

            if ($positionAsterix === false && strpos($pathRegex, '!') === false) {
                // no regular expression characters, use regular comparisson
                if ($path === $pathRegex) {
                    return true;
                }

                continue;
            }

            $lengthPathRegex = strlen($pathRegex);
            $hasEndAsterix = $positionAsterix === $lengthPathRegex - 2 && $pathRegex[$lengthPathRegex - 1] == self::ASTERIX;

            // match everything beginning with a string, use regular string comparisson
            if (strncmp($pathRegex, $path, $positionAsterix) === 0) {
                if ($hasEndAsterix) {
                    return true;
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
                return true;
            }
        }

        return false;
    }

}
