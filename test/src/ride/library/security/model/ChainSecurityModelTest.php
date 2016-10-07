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

        $modelMock = $this->getMockBuilder('ride\\library\\security\\model\\ChainableSecurityModel')
                          ->getMock();
        $modelMock->expects($this->once())
                  ->method('ping')
                  ->will($this->returnValue(true));

        $this->model->addSecurityModel($modelMock);

        $this->assertEquals('[' . get_class($modelMock) . ']', (string) $this->model);

        $modelMock2 = $this->getMockBuilder('ride\\library\\security\\model\\ChainableSecurityModel')
                           ->getMock();
        $modelMock2->expects($this->once())
                   ->method('ping')
                   ->will($this->returnValue(true));

        $this->model->addSecurityModel($modelMock2);

        $this->assertEquals('[' . get_class($modelMock) . ', ' . get_class($modelMock2) . ']', (string) $this->model);
    }

    public function testAddSecurityModel() {
        $modelMock = $this->getMockBuilder('ride\\library\\security\\model\\ChainableSecurityModel')
                          ->getMock();

        $this->assertFalse($this->model->addSecurityModel($modelMock));
        $this->assertEquals(array(), $this->model->getSecurityModels());

        $modelMock = $this->getMockBuilder('ride\\library\\security\\model\\ChainableSecurityModel')
                          ->getMock();
        $modelMock->expects($this->once())
                  ->method('ping')
                  ->will($this->returnValue(true));

        $this->assertTrue($this->model->addSecurityModel($modelMock));
        $this->assertEquals(array($modelMock), $this->model->getSecurityModels());
    }

    public function testRemoveSecurityModel() {
        $modelMock = $this->getMockBuilder('ride\\library\\security\\model\\ChainableSecurityModel')
                          ->getMock();
        $modelMock->expects($this->once())
                  ->method('ping')
                  ->will($this->returnValue(true));

        $this->model->addSecurityModel($modelMock);
        $this->assertEquals(array($modelMock), $this->model->getSecurityModels());

        $modelMock2 = $this->getMockBuilder('ride\\library\\security\\model\\ChainableSecurityModel')
                           ->getMock();

        $this->assertFalse($this->model->removeSecurityModel($modelMock2));
        $this->assertEquals(array($modelMock), $this->model->getSecurityModels());

        $this->assertTrue($this->model->removeSecurityModel($modelMock));
        $this->assertEquals(array(), $this->model->getSecurityModels());
    }

    public function testPing() {
        $this->assertFalse($this->model->ping());

        $modelMock = $this->getMockBuilder('ride\\library\\security\\model\\ChainableSecurityModel')
                          ->getMock();
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

        $modelMock = $this->getMockBuilder('ride\\library\\security\\model\\ChainableSecurityModel')
                          ->getMock();
        $modelMock->expects($this->once())
                  ->method('ping')
                  ->will($this->returnValue(true));
        $modelMock->expects($this->once())
                  ->method('getSecuredPaths')
                  ->will($this->returnValue(array($path1, $path2)));

        $modelMock2 = $this->getMockBuilder('ride\\library\\security\\model\\ChainableSecurityModel')
                           ->getMock();
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

        $modelMock = $this->getMockBuilder('ride\\library\\security\\model\\ChainableSecurityModel')
                          ->getMock();
        $modelMock->expects($this->once())
                  ->method('ping')
                  ->will($this->returnValue(true));
        $modelMock->expects($this->once())
                  ->method('setSecuredPaths')
                  ->with($this->equalTo($securedPaths))
                  ->will($this->returnValue(null));

        $modelMock2 = $this->getMockBuilder('ride\\library\\security\\model\\ChainableSecurityModel')
                           ->getMock();
        $modelMock2->expects($this->once())
                   ->method('ping')
                   ->will($this->returnValue(true));
        $modelMock2->expects($this->never())
                   ->method('setSecuredPaths');

        $this->model->addSecurityModel($modelMock);
        $this->model->addSecurityModel($modelMock2);

        $this->model->setSecuredPaths($securedPaths);
    }

    public function testSetGrantedPermissionsToRole() {
        $permissions = array('permission');
        $roleMock = $this->getMockBuilder('ride\\library\\security\\model\\Role')
                         ->getMock();

        $modelMock = $this->getMockBuilder('ride\\library\\security\\model\\ChainableSecurityModel')
                          ->getMock();
        $modelMock->expects($this->once())
                  ->method('ping')
                  ->will($this->returnValue(true));
        $modelMock->expects($this->once())
                  ->method('ownsRole')
                  ->with($this->equalTo($roleMock))
                  ->will($this->returnValue(false));
        $modelMock->expects($this->never())
                  ->method('setGrantedPermissionsToRole');

        $modelMock2 = $this->getMockBuilder('ride\\library\\security\\model\\ChainableSecurityModel')
                           ->getMock();
        $modelMock2->expects($this->once())
                   ->method('ping')
                   ->will($this->returnValue(true));
        $modelMock2->expects($this->once())
                   ->method('ownsRole')
                   ->with($this->equalTo($roleMock))
                   ->will($this->returnValue(true));
        $modelMock2->expects($this->once())
                   ->method('setGrantedPermissionsToRole')
                   ->with($this->equalTo($roleMock), $this->equalTo($permissions));

        $this->model->addSecurityModel($modelMock);
        $this->model->addSecurityModel($modelMock2);

        $this->model->setGrantedPermissionsToRole($roleMock, $permissions);
    }

    public function testSetAllowedPathsToRole() {
        $paths = array('/path');
        $roleMock = $this->getMockBuilder('ride\\library\\security\\model\\Role')
                         ->getMock();

        $modelMock = $this->getMockBuilder('ride\\library\\security\\model\\ChainableSecurityModel')
                          ->getMock();
        $modelMock->expects($this->once())
                  ->method('ping')
                  ->will($this->returnValue(true));
        $modelMock->expects($this->once())
                  ->method('ownsRole')
                  ->with($this->equalTo($roleMock))
                  ->will($this->returnValue(false));
        $modelMock->expects($this->never())
                  ->method('setAllowedPathsToRole');

        $modelMock2 = $this->getMockBuilder('ride\\library\\security\\model\\ChainableSecurityModel')
                           ->getMock();
        $modelMock2->expects($this->once())
                   ->method('ping')
                   ->will($this->returnValue(true));
        $modelMock2->expects($this->once())
                   ->method('ownsRole')
                   ->with($this->equalTo($roleMock))
                   ->will($this->returnValue(true));
        $modelMock2->expects($this->once())
                   ->method('setAllowedPathsToRole')
                   ->with($this->equalTo($roleMock), $this->equalTo($paths));

        $this->model->addSecurityModel($modelMock);
        $this->model->addSecurityModel($modelMock2);

        $this->model->setAllowedPathsToRole($roleMock, $paths);
    }

    public function testSetRolesToUser() {
        $userMock = $this->getMockBuilder('ride\\library\\security\\model\\User')
                         ->getMock();
        $roleMock = $this->getMockBuilder('ride\\library\\security\\model\\Role')
                         ->getMock();
        $roles = array($roleMock);

        $modelMock = $this->getMockBuilder('ride\\library\\security\\model\\ChainableSecurityModel')
                          ->getMock();
        $modelMock->expects($this->once())
                  ->method('ping')
                  ->will($this->returnValue(true));
        $modelMock->expects($this->once())
                  ->method('ownsUser')
                  ->with($this->equalTo($userMock))
                  ->will($this->returnValue(false));
        $modelMock->expects($this->never())
                  ->method('setRolesToUser');

        $modelMock2 = $this->getMockBuilder('ride\\library\\security\\model\\ChainableSecurityModel')
                           ->getMock();
        $modelMock2->expects($this->once())
                   ->method('ping')
                   ->will($this->returnValue(true));
        $modelMock2->expects($this->once())
                   ->method('ownsUser')
                   ->with($this->equalTo($userMock))
                   ->will($this->returnValue(true));
        $modelMock2->expects($this->once())
                   ->method('setRolesToUser')
                   ->with($this->equalTo($userMock), $this->equalTo($roles));

        $this->model->addSecurityModel($modelMock);
        $this->model->addSecurityModel($modelMock2);

        $this->model->setRolesToUser($userMock, $roles);
    }

    /**
     * @dataProvider providerGetUserBy
     */
    public function testGetUserBy($method, $query) {
        $userMock = $this->getMockBuilder('ride\\library\\security\\model\\User')
                         ->getMock();

        $modelMock = $this->getMockBuilder('ride\\library\\security\\model\\ChainableSecurityModel')
                          ->getMock();
        $modelMock->expects($this->once())
                  ->method('ping')
                  ->will($this->returnValue(true));
        $modelMock->expects($this->once())
                  ->method($method)
                  ->with($this->equalTo($query))
                  ->will($this->returnValue(null));

        $modelMock2 = $this->getMockBuilder('ride\\library\\security\\model\\ChainableSecurityModel')
                           ->getMock();
        $modelMock2->expects($this->once())
                   ->method('ping')
                   ->will($this->returnValue(true));
        $modelMock2->expects($this->once())
                   ->method($method)
                   ->with($this->equalTo($query))
                   ->will($this->returnValue($userMock));

        $this->model->addSecurityModel($modelMock);
        $this->model->addSecurityModel($modelMock2);

        $result = $this->model->$method($query);

        $this->assertEquals($userMock, $result);
    }

    public function providerGetUserBy() {
        return array(
            array('getUserById', 'id'),
            array('getUserByUsername', 'username'),
            array('getUserByEmail', 'e@ma.il'),
        );
    }

    public function testGetUsers() {

    }

    public function testCountUsers() {
        $options = array('query' => 'test');

        $modelMock = $this->getMockBuilder('ride\\library\\security\\model\\ChainableSecurityModel')
                          ->getMock();
        $modelMock->expects($this->once())
                  ->method('ping')
                  ->will($this->returnValue(true));
        $modelMock->expects($this->once())
                  ->method('countUsers')
                  ->with($this->equalTo($options))
                  ->will($this->returnValue(2));

        $modelMock2 = $this->getMockBuilder('ride\\library\\security\\model\\ChainableSecurityModel')
                           ->getMock();
        $modelMock2->expects($this->once())
                   ->method('ping')
                   ->will($this->returnValue(true));
        $modelMock2->expects($this->once())
                   ->method('countUsers')
                   ->with($this->equalTo($options))
                   ->will($this->returnValue(3));

        $this->model->addSecurityModel($modelMock);
        $this->model->addSecurityModel($modelMock2);

        $result = $this->model->countUsers($options);

        $this->assertEquals($result, 5);
    }

}
