<?php
/**
 * Copyright (c) 2013 Christopher Schäpers <christopher@schaepers.it>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

class Test_Appconfig extends PHPUnit_Framework_TestCase {
	private function fillDb() {
		$query = \OC_DB::prepare('INSERT INTO `*PREFIX*appconfig` VALUES (?, ?, ?)');

		$query->execute(array('testapp', 'enabled', 'true'));
		$query->execute(array('testapp', 'installed_version', '1.2.3'));
		$query->execute(array('testapp', 'depends_on', 'someapp'));
		$query->execute(array('testapp', 'deletethis', 'deletethis'));
		$query->execute(array('testapp', 'key', 'value'));

		$query->execute(array('someapp', 'key', 'value'));
		$query->execute(array('someapp', 'otherkey', 'othervalue'));

		$query->execute(array('123456', 'key', 'value'));
		$query->execute(array('123456', 'enabled', 'false'));

		$query->execute(array('anotherapp', 'key', 'value'));
		$query->execute(array('anotherapp', 'enabled', 'false'));
	}

	public function testGetApps() {
		$this->fillDb();

		$query = \OC_DB::prepare('SELECT DISTINCT `appid` FROM `*PREFIX*appconfig`');
		$result = $query->execute();
		$expected = array();
		while ($row = $result->fetchRow()) {
			$expected[] = $row['appid'];
		}
		$apps = \OC_Appconfig::getApps();
		$this->assertEquals($expected, $apps);
	}

	public function testGetKeys() {
		$query = \OC_DB::prepare('SELECT `configkey` FROM `*PREFIX*appconfig` WHERE `appid` = ?');
		$result = $query->execute(array('testapp'));
		$expected = array();
		while($row = $result->fetchRow()) {
			$expected[] = $row["configkey"];
		}
		$keys = \OC_Appconfig::getKeys('testapp');
		$this->assertEquals($expected, $keys);
	}

	public function testGetValue() {
		$query = \OC_DB::prepare('SELECT `configvalue` FROM `*PREFIX*appconfig` WHERE `appid` = ? AND `configkey` = ?');
		$result = $query->execute(array('testapp', 'installed_version'));
		$expected = $result->fetchRow();
		$value = \OC_Appconfig::getValue('testapp', 'installed_version');
		$this->assertEquals($expected['configvalue'], $value);

		$value = \OC_Appconfig::getValue('testapp', 'nonexistant');
		$this->assertNull($value);

		$value = \OC_Appconfig::getValue('testapp', 'nonexistant', 'default');
		$this->assertEquals('default', $value);
	}

	public function testHasKey() {
		$value = \OC_Appconfig::hasKey('testapp', 'installed_version');
		$this->assertTrue($value);

		$value = \OC_Appconfig::hasKey('nonexistant', 'nonexistant');
		$this->assertFalse($value);
	}

	public function testSetValue() {
		\OC_Appconfig::setValue('testapp', 'installed_version', '1.33.7');
		$query = \OC_DB::prepare('SELECT `configvalue` FROM `*PREFIX*appconfig` WHERE `appid` = ? AND `configkey` = ?');
		$result = $query->execute(array('testapp', 'installed_version'));
		$value = $result->fetchRow();
		$this->assertEquals('1.33.7', $value['configvalue']);

		\OC_Appconfig::setValue('someapp', 'somekey', 'somevalue');
		$query = \OC_DB::prepare('SELECT `configvalue` FROM `*PREFIX*appconfig` WHERE `appid` = ? AND `configkey` = ?');
		$result = $query->execute(array('someapp', 'somekey'));
		$value = $result->fetchRow();
		$this->assertEquals('somevalue', $value['configvalue']);
	}

	/**
	 * @expectedException \Doctrine\DBAL\DBALException
	*/
	public function testSetValueNull() {
		\OC_Appconfig::setValue('testapp', 'installed_version', null);
	}

	/**
	 * @expectedException \Doctrine\DBAL\DBALException
	*/
	public function testSetValueEmptyString() {
		\OC_Appconfig::setValue('testapp', '', '1.33.7');
	}

	public function testDeleteKey() {
		\OC_Appconfig::deleteKey('testapp', 'deletethis');
		$query = \OC_DB::prepare('SELECT `configvalue` FROM `*PREFIX*appconfig` WHERE `appid` = ? AND `configkey` = ?');
		$query->execute(array('testapp', 'deletethis'));
		$result = (bool)$query->fetchRow();
		$this->assertFalse($result);
	}

	public function testDeleteApp() {
		\OC_Appconfig::deleteApp('someapp');
		$query = \OC_DB::prepare('SELECT `configkey` FROM `*PREFIX*appconfig` WHERE `appid` = ?');
		$query->execute(array('someapp'));
		$result = (bool)$query->fetchRow();
		$this->assertFalse($result);
	}

	public function testGetValues() {
		$this->assertFalse(\OC_Appconfig::getValues('testapp', 'enabled'));

		$query = \OC_DB::prepare('SELECT `configkey`, `configvalue` FROM `*PREFIX*appconfig` WHERE `appid` = ?');
		$query->execute(array('testapp'));
		$expected = array();
		while ($row = $query->fetchRow()) {
			$expected[$row['configkey']] = $row['configvalue'];
		}
		$values = \OC_Appconfig::getValues('testapp', false);
		$this->assertEquals($expected, $values);

		$query = \OC_DB::prepare('SELECT `appid`, `configvalue` FROM `*PREFIX*appconfig` WHERE `configkey` = ?');
		$query->execute(array('enabled'));
		$expected = array();
		while ($row = $query->fetchRow()) {
			$expected[$row['appid']] = $row['configvalue'];
		}
		$values = \OC_Appconfig::getValues(false, 'enabled');
		$this->assertEquals($expected, $values);
	}
}
