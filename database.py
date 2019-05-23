#!/usr/bin/env python
# -*- coding: utf-8 -*-

from sys import exit
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

from exceptions import DatabaseException, MultiSFCException
from utils import ERROR
from bson import ObjectId
import logging


logger = logging.getLogger('database')


class DatabaseConnection:

    # We don't need Singleton anymore, as we are using multi-processing instead of multi-threading in web server.
    # So all forked process in requests must open a new connection to the database
    #
    __instance = None

    # Singleton
    def __new__(cls, *args, **kwargs):
        if not cls.__instance:
            cls.__instance = super().__new__(cls)

        return cls.__instance

    def __init__(self):
        self.client = MongoClient(host='localhost', port=27017, maxPoolSize=200)

        logger.debug("Opening database connection...")

        try:
            # this command is just used to verify the connection to the Mongo Database
            # see MongoClient() docs
            self.client.admin.command('ismaster')
        except ConnectionFailure as e:
            logger.critical("MongoDB Server not available! %s", e)
            exit(1)

        self.db = self.client.Holistic

    def insert_vnf_package(self, category, vnfd_name, dir_id, vnf_type, platform, description):
        """
        Raises
        ------
            DatabaseException
        """
        try:
            res = self.db.Catalog.insert_one({
                'category': category,
                'vnfd_name': vnfd_name,
                'dir_id': dir_id,
                'vnf_type': vnf_type,
                'platform': platform,
                'description': description
                })
            if not res.inserted_id:
                raise MultiSFCException('Failed on inserting this VNF Package in database.')

        # used generic Exception to catch the MultiSFCException and any other unknown exceptions
        except Exception as e:
            logger.error(e)
            raise DatabaseException(ERROR, str(e))

    def remove_vnf_package(self, vnf_pkg_id):
        """
        Raises
        ------
            DatabaseException
        """
        try:
            data = self.db.Catalog.delete_one({
                        '_id': ObjectId(vnf_pkg_id)
                        })

            if not data.deleted_count:
                raise MultiSFCException('Failed on removing VNF Package %s from the database.' % vnf_pkg_id)

        except Exception as e:
            logger.error(e)
            raise DatabaseException(ERROR, str(e))

    def list_catalog(self, vnf_pkg_id=None, category=None,
                     vnfd_name=None, dir_id=None, platform=None):
        """
        Retrieves a list of VNF Packages stored in database.

        Raises
        -----
            DatabaseException
        """
        criteria = {}
        if vnf_pkg_id:
            criteria['_id'] = ObjectId(vnf_pkg_id)
        if category:
            criteria['category'] = category
        if vnfd_name:
            criteria['vnfd_name'] = vnfd_name
        if dir_id:
            criteria['dir_id'] = dir_id
        if platform:
            criteria['platform'] = platform

        try:
            catalog = self.db.Catalog.find(criteria)

            data = []
            for vnf in catalog:
                if isinstance(vnf['_id'], ObjectId):
                    vnf['_id'] = str(vnf['_id'])
                data.append(vnf)
            return data
        except Exception as e:
            logger.error(e)
            raise DatabaseException(ERROR, str(e))

    def insert_vnf_instance(self, vnf_pkg_id, vnfd_id, vnf_id):
        """Inserts data in VNF_Instances collection in MongoDB

        :param vnf_pkg_id: local VNF Package ID
        :param vnfd_id: NFVO VNFD ID
        :param vnf_id: NFVO VNF ID

        Raises
        -----
            DatabaseException
        """
        try:
            data = self.db.VNF_Instances.insert_one({
                        'vnf_pkg_id': vnf_pkg_id,
                        'vnfd_id': vnfd_id,
                        'vnf_id': vnf_id
                        })
            if not data.inserted_id:
                raise MultiSFCException("VNF Instance not inserted in database!")

        except Exception as e:
            logger.error(e)
            raise DatabaseException(ERROR, str(e))

    def remove_vnf_instance(self, vnf_instance_id):
        """Removes a VNF Instance from the database

        :param vnf_instance_id: the local identifier for the MongoDB (i.e., the _id str value)

        Raises
        -----
            DatabaseException
        """
        try:
            res = self.db.VNF_Instances.delete_one({
                        '_id': ObjectId(vnf_instance_id)
                        })
            if not res.deleted_count:
                raise MultiSFCException("VNF Instance not deleted from database!")

        except Exception as e:
            logger.error(e)
            raise DatabaseException(ERROR, str(e))

    def list_vnf_instances(self, vnf_instance_id=None,
                           vnf_pkg_id=None, vnfd_id=None, vnf_id=None):
        """Returns a list of VNF Instances stored in MongoDB

        The function arguments are used to create the search criteria for the MongoDB.
        To get all VNF Instances stored in database just call this function without arguments.

        :param vnf_instance_id:
        :param vnf_pkg_id:
        :param vnfd_id:
        :param vnf_id:
        :return: A list of VNF Instances stored in database

        Raises
        -----
            DatabaseException
        """
        criteria = {}
        if vnf_instance_id:
            criteria['_id'] = ObjectId(vnf_instance_id)
        if vnf_pkg_id:
            criteria['vnf_pkg_id'] = vnf_pkg_id
        if vnfd_id:
            criteria['vnfd_id'] = vnfd_id
        if vnf_id:
            criteria['vnf_id'] = vnf_id

        try:
            vnf_instances = self.db.VNF_Instances.find(criteria)

            data = []
            for vnf in vnf_instances:
                if isinstance(vnf['_id'], ObjectId):
                    vnf['_id'] = str(vnf['_id'])
                data.append(vnf)
            return data

        except Exception as e:
            logger.error(e)
            raise DatabaseException(ERROR, str(e))

    def insert_sfc_instance(self, vnf_instances, nsd_id, ns_id, ns_name, platform):
        """Inserts data in SFC_Instances collection in MongoDB

        :param vnf_instances: a list or dict with all vnf_instance_id stored in MongoDB
        :param nsd_id: SFC Descriptor ID (NVFO VNFFGD ID or NSD ID)
        :param ns_id: SFC Instance ID (NFVO VNFFG or NS ID)
        :param ns_name: Name of the SFC Instance
        :param platform: The platform which runs this SFC

        Raises
        ------
            DatabaseException
        """
        try:
            data = self.db.SFC_Instances.insert_one({
                        'vnf_instances': vnf_instances,
                        'nsd_id': nsd_id,
                        'ns_id': ns_id,
                        'ns_name': ns_name,
                        'platform': platform
                        })
            if not data.inserted_id:
                raise MultiSFCException("SFC Instance not inserted in database!")

        except Exception as e:
            logger.error(e)
            raise DatabaseException(ERROR, str(e))

    def remove_sfc_instance(self, sfc_instance_id):
        """Removes a VNF Instance from the database

        :param sfc_instance_id: the local identifier for the MongoDB (i.e., the _id str value)

        Raises
        ------
            DatabaseException
        """
        try:
            data = self.db.SFC_Instances.delete_one({
                        '_id': ObjectId(sfc_instance_id)
                        })
            if not data.deleted_count:
                raise MultiSFCException("SFC Instance not deleted from database!")

        except Exception as e:
            logger.error(e)
            raise DatabaseException(ERROR, str(e))

    def list_sfc_instances(self, sfc_instance_id=None, vnf_instances=None,
                           nsd_id=None, ns_id=None, ns_name=None, platform=None):
        """Returns a list of SFC Instances stored in MongoDB

        The function arguments are used to create the search criteria for the MongoDB.
        To get all SFC Instances stored in database just call this function without arguments.

        :param sfc_instance_id: the unique identifier generated by mongodb
        :param vnf_instances: a list of VNF Instances
        :param nsd_id: an NSD id or a VNFFGD id (NFVO id)
        :param ns_id: an NS id or a VNFFG id (NFVO id)
        :param ns_name:
        :param platform:
        :return: A list of SFC Instances stored in database

        Raises
        ------
            DatabaseException
        """
        criteria = {}
        if sfc_instance_id:
            criteria['_id'] = ObjectId(sfc_instance_id)
        if vnf_instances:
            criteria['vnf_instances'] = vnf_instances
        if nsd_id:
            criteria['nsd_id'] = nsd_id
        if ns_id:
            criteria['ns_id'] = ns_id
        if ns_name:
            criteria['ns_name'] = ns_name
        if platform:
            criteria['platform'] = platform

        try:
            sfc_instances = self.db.SFC_Instances.find(criteria)

            data = []
            for sfc in sfc_instances:
                if isinstance(sfc['_id'], ObjectId):
                    sfc['_id'] = str(sfc['_id'])
                data.append(sfc)
            return data

        except Exception as e:
            logger.error(e)
            raise DatabaseException(ERROR, str(e))


if __name__ == '__main__':
    import sys

    # Used to clean VNF_Instances and SFC_Instances performance tests database data
    if len(sys.argv) == 2 and sys.argv[1] == 'clean':
        database = DatabaseConnection()

        result = database.db.SFC_Instances.delete_many({})
        print('Removed %s SFC_Instances from database.' % result.deleted_count)

        result = database.db.VNF_Instances.delete_many({})
        print('Removed %s VNF_Instances from database.' % result.deleted_count)

    else:
        print('Usage: %s clean' % sys.argv[0])
