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
        foreach ($pathRegexes as $regex) {
            $regex = str_replace(PathMatcher::ASTERIX . PathMatcher::ASTERIX, '||||||', $regex);
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