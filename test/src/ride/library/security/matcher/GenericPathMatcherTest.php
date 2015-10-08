<?php

namespace ride\library\security\matcher;

use \PHPUnit_Framework_TestCase;

class GenericPathMatcherTest extends PHPUnit_Framework_TestCase {

    /**
     * @dataProvider providerMatchPath
     */
    public function testMatchPath($expected, $path, $method, $paths) {
        $pathMatcher = new GenericPathMatcher();
        $result = $pathMatcher->matchPath($path, $method, $paths);

        $this->assertEquals($expected, $result);
    }

    public function providerMatchPath() {
        return array(
            array(false, '/path', 'GET', array()),
            array(false, '/path', 'GET', array('/sme')),
            array(true, '/path', 'GET', array('/path')),
            array(true, '/path', 'GET', array('/sme', '/path')),
            array(false, '/path/to/file', 'GET', array('/sme', '/path')),
            array(true, '/path/to/file', 'GET', array('/path/*/file')),
            array(true, '/path/from/file', 'GET', array('/path/*/file')),
            array(false, '/path/to/my/file', 'GET', array('/path/*/file')),
            array(false, '/path/to/file', 'GET', array('/path/*')),
            array(true, '/path/to/file', 'GET', array('/path/**')),
            array(true, '/path', 'GET', array('/path [GET]')),
            array(false, '/path', 'GET', array('/path [POST]')),
            array(false, '/path/to/file', 'GET', array('/path/**', '!/path/to/file')),
            array(true, '/path/to/file', 'GET', array('/path/**', '!/path/to/file', '/p**')),
            array(true, '/path/to/file', 'GET', array('/path/**', '!/path/to/file [POST]')),
            array(false, '/path/to/file', 'GET', array('/path/**', '!/path/to/file [GET]')),
        );
    }

}
