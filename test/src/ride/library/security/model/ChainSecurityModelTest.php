<?php

namespace ride\library\security\model;

use \PHPUnit_Framework_TestCase;

class ChainSecurityModelTest extends PHPUnit_Framework_TestCase {

    public function setUp() {
        $this->model = new ChainSecurityModel();
    }

    public function testConstruct() {
        $this->assertEquals(array(), $this->model->getSecurityModels());
    }

    public function testToString() {
        $this->assertEquals('[]', (string) $this->model);

        $modelMock = $this->getMock('ride\\library\\security\\model\\ChainableSecurityModel');
        $modelMock->expects($this->once())
                  ->method('ping')
                  ->will($this->returnValue(true));

        $this->model->addSecurityModel($modelMock);

        $this->assertEquals('[' . get_class($modelMock) . ']', (string) $this->model);

        $modelMock2 = $this->getMock('ride\\library\\security\\model\\ChainableSecurityModel');
        $modelMock2->expects($this->once())
                   ->method('ping')
                   ->will($this->returnValue(true));

        $this->model->addSecurityModel($modelMock2);

        $this->assertEquals('[' . get_class($modelMock) . ', ' . get_class($modelMock2) . ']', (string) $this->model);
    }

    public function testAddSecurityModel() {
        $modelMock = $this->getMock('ride\\library\\security\\model\\ChainableSecurityModel');

        $this->assertFalse($this->model->addSecurityModel($modelMock));
        $this->assertEquals(array(), $this->model->getSecurityModels());

        $modelMock = $this->getMock('ride\\library\\security\\model\\ChainableSecurityModel');
        $modelMock->expects($this->once())
                  ->method('ping')
                  ->will($this->returnValue(true));

        $this->assertTrue($this->model->addSecurityModel($modelMock));
        $this->assertEquals(array($modelMock), $this->model->getSecurityModels());
    }

    public function testRemoveSecurityModel() {
        $modelMock = $this->getMock('ride\\library\\security\\model\\ChainableSecurityModel');
        $modelMock->expects($this->once())
                  ->method('ping')
                  ->will($this->returnValue(true));

        $this->model->addSecurityModel($modelMock);
        $this->assertEquals(array($modelMock), $this->model->getSecurityModels());

        $modelMock2 = $this->getMock('ride\\library\\security\\model\\ChainableSecurityModel');

        $this->assertFalse($this->model->removeSecurityModel($modelMock2));
        $this->assertEquals(array($modelMock), $this->model->getSecurityModels());

        $this->assertTrue($this->model->removeSecurityModel($modelMock));
        $this->assertEquals(array(), $this->model->getSecurityModels());
    }

    public function testPing() {
        $this->assertFalse($this->model->ping());

        $modelMock = $this->getMock('ride\\library\\security\\model\\ChainableSecurityModel');
        $modelMock->expects($this->once())
                  ->method('ping')
                  ->will($this->returnValue(true));

        $this->model->addSecurityModel($modelMock);

        $this->assertTrue($this->model->ping());
    }

    public function testGetSecuredPaths() {
        $path1 = '/path1';
        $path2 = '/path2';
        $path3 = '/path3';
        $path4 = '/path4';

        $modelMock = $this->getMock('ride\\library\\security\\model\\ChainableSecurityModel');
        $modelMock->expects($this->once())
                  ->method('ping')
                  ->will($this->returnValue(true));
        $modelMock->expects($this->once())
                  ->method('getSecuredPaths')
                  ->will($this->returnValue(array($path1, $path2)));

        $modelMock2 = $this->getMock('ride\\library\\security\\model\\ChainableSecurityModel');
        $modelMock2->expects($this->once())
                   ->method('ping')
                   ->will($this->returnValue(true));
        $modelMock2->expects($this->once())
                   ->method('getSecuredPaths')
                   ->will($this->returnValue(array($path3, $path4)));

        $this->model->addSecurityModel($modelMock);
        $this->model->addSecurityModel($modelMock2);

        $expected = array(
            $path1 => $path1,
            $path2 => $path2,
            $path3 => $path3,
            $path4 => $path4,
        );

        $this->assertEquals($expected, $this->model->getSecuredPaths());
    }

    public function testSetSecuredPaths() {
        $securedPaths = array(
            '/path1',
            '/path2',
        );

        $modelMock = $this->getMock('ride\\library\\security\\model\\ChainableSecurityModel');
        $modelMock->expects($this->once())
                  ->method('ping')
                  ->will($this->returnValue(true));
        $modelMock->expects($this->once())
                  ->method('setSecuredPaths')
                  ->with($this->equalTo($securedPaths))
                  ->will($this->returnValue(null));

        $modelMock2 = $this->getMock('ride\\library\\security\\model\\ChainableSecurityModel');
        $modelMock2->expects($this->once())
                   ->method('ping')
                   ->will($this->returnValue(true));
        $modelMock2->expects($this->never())
                   ->method('setSecuredPaths');

        $this->model->addSecurityModel($modelMock);
        $this->model->addSecurityModel($modelMock2);

        $this->model->setSecuredPaths($securedPaths);
    }

}
