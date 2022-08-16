<?php

declare(strict_types=1);

/**
 * @copyright Copyright (c) 2019, Roeland Jago Douma <roeland@famdouma.nl>
 *
 * @author Roeland Jago Douma <roeland@famdouma.nl>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */
namespace OC\Core\Db;

use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Db\QBMapper;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IDBConnection;

class LoginFlowV2Mapper extends QBMapper {
	private const lifetime = 1200;

	/** @var ITimeFactory */
	private $timeFactory;

	public function __construct(IDBConnection $db, ITimeFactory $timeFactory) {
		parent::__construct($db, 'login_flow_v2', LoginFlowV2::class);
		$this->timeFactory = $timeFactory;
	}

	/**
	 * @param string $pollToken
	 * @return LoginFlowV2
	 * @throws DoesNotExistException
	 */
	public function getByPollToken(string $pollToken): LoginFlowV2 {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from($this->getTableName())
			->where(
				$qb->expr()->eq('poll_token', $qb->createNamedParameter($pollToken))
			);

		$entity = $this->findEntity($qb);
		return $this->validateTimestamp($entity);
	}

	/**
	 * @param string $loginToken
	 * @return LoginFlowV2
	 * @throws DoesNotExistException
	 */
	public function getByLoginToken(string $loginToken): LoginFlowV2 {
		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from($this->getTableName())
			->where(
				$qb->expr()->eq('login_token', $qb->createNamedParameter($loginToken))
			);

		$entity = $this->findEntity($qb);
		return $this->validateTimestamp($entity);
	}

	public function cleanup(): void {
		$qb = $this->db->getQueryBuilder();
		$qb->delete($this->getTableName())
			->where(
				$qb->expr()->lt('timestamp', $qb->createNamedParameter($this->timeFactory->getTime() - self::lifetime))
			);

		$qb->execute();
	}

	// @kjh
	// insert or update last login IP
	public function insertLastLoginIP($userId, $loginIP): void {
		$qb = $this->db->getQueryBuilder();
		$lastLoginIP = $this->getLastLoginIP($userId);
		if($lastLoginIP !=''){
			$qb->update('preferences')
			->set('configvalue', $qb->createNamedParameter($loginIP))
			->where($qb->expr()->eq('userid', $qb->createNamedParameter($userId)))
			->andWhere($qb->expr()->eq('appid', $qb->createNamedParameter('login')))
			->andWhere($qb->expr()->eq('configkey', $qb->createNamedParameter('lastLoginIP')));
		} else {
			$qb->insert('preferences')
			->setValue('userid', $qb->createNamedParameter($userId))
			->setValue('appid', $qb->createNamedParameter('login'))
			->setValue('configkey', $qb->createNamedParameter('lastLoginIP'))
			->setValue('configvalue', $qb->createNamedParameter($loginIP));
		}
		$qb->execute();
	}

	// update user 2fa setting
	public function updateTFASetting($userId, $val): void {
		$this->updateProviderSetting($userId, $val);
	}

	// check last login IP
	public function checkLoginIp($userId, $currentLoginIP){
		$lastLoginIP = $this->getLastLoginIP($userId);
		$lastDomain = $this->getDomain($lastLoginIP);
		$currentDomain = $this->getDomain($currentLoginIP);
		if($lastDomain == $currentDomain) $this->updateProviderSetting($userId, 0);
		else $this->updateProviderSetting($userId, 1);
	}

	// update provider setting
	private function updateProviderSetting($userId, $val): void {
		$qb = $this->db->getQueryBuilder();
		$qb->update('twofactor_providers')
			->set('enabled', $qb->createNamedParameter($val))
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($userId)))
			->andWhere($qb->expr()->eq('provider_id', $qb->createNamedParameter('email')));
		$qb->execute();
	}

	// get last login IP
	private function getLastLoginIP($userId) {
		$qb = $this->db->getQueryBuilder();
		$qb->select('configvalue')
			->from('preferences')
			->where($qb->expr()->eq('userid', $qb->createNamedParameter($userId)))
			->andWhere($qb->expr()->eq('appid', $qb->createNamedParameter('login')))
			->andWhere($qb->expr()->eq('configkey', $qb->createNamedParameter('lastLoginIP')));
		$result = $qb->executeQuery();
		$one = $result->fetchOne();
		// $raw = $result->fetchAll();
		$result->closeCursor();
		if (!$one) return '';
		return $one;
	}
	
	// determine outgoing or incoming
	private function getDomain($ip)
	{
		if(!$ip) return '';
		$domain = explode('.', $ip);
		return $domain[0];
	}

	// end

	/**
	 * @param LoginFlowV2 $flowV2
	 * @return LoginFlowV2
	 * @throws DoesNotExistException
	 */
	private function validateTimestamp(LoginFlowV2 $flowV2): LoginFlowV2 {
		if ($flowV2->getTimestamp() < ($this->timeFactory->getTime() - self::lifetime)) {
			$this->delete($flowV2);
			throw new DoesNotExistException('Token expired');
		}

		return $flowV2;
	}
}
