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
            array(true, '/admin/security', 'GET', array(
                '/admin**',
                '/api**',
                '!/api/v1/surveys** [GET]',
                '!/api/v1/survey-questions** [GET]',
                '!/api/v1/survey-entry-answers [POST]',
                '!/api/v1/survey-evaluations [GET]',
                '!/api/v1/survey-evaluations/*/evaluate/* [POST]',
                '!/api/v1/survey-entries [POST,PATCH]',
            )),
            array(false, '/api/v1/surveys/3', 'GET', array(
                '/admin**',
                '/api**',
                '!/api/v1/surveys** [GET]',
                '!/api/v1/survey-questions** [GET]',
                '!/api/v1/survey-entry-answers [POST]',
                '!/api/v1/survey-evaluations [GET]',
                '!/api/v1/survey-evaluations/*/evaluate/* [POST]',
                '!/api/v1/survey-entries [POST,PATCH]',
            )),
        );
    }

}
