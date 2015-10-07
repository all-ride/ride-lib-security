<?php

namespace ride\library\security\matcher;

/**
 * Interface for a path matcher
 */
interface PathMatcher {

    /**
     * Asterix value for the route matcher
     * @var string
     */
    const ASTERIX = '*';

    /**
     * Checks if the provided path matches one of the provided path regular
     * expressions
     * @param string $path Path the match
     * @param string $method Request method to check
     * @param array $pathRegexes Array with path regular expressions
     * @return boolean True if matched, false otherwise
     */
    public function matchPath($path, $method, array $pathRegexes);

}
