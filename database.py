#!/usr/bin/env python
# -*- coding: utf-8 -*-

from sys import exit
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from utils import OK, ERROR
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
        try:
            res = self.db.Catalog.insert_one({
                'category': category,
                'vnfd_name': vnfd_name,
                'dir_id': dir_id,
                'vnf_type': vnf_type,
                'platform': platform,
                'description': description
                })
        except Exception as e:
            logger.error(e)
            return ERROR, e

        return OK, res

    def remove_vnf_package(self, vnf_pkg_id):
        try:
            data = self.db.Catalog.delete_one({
                        '_id': ObjectId(vnf_pkg_id)
                        })
        except Exception as e:
            return ERROR, e

        if data.deleted_count == 1:
            return OK
        else:
            return ERROR

    def list_catalog(self, vnf_pkg_id=None, category=None,
                     vnfd_name=None, dir_id=None, platform=None):

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
            return OK, data
        except Exception as e:
            logger.error(e)
            return ERROR, e

    def insert_vnf_instance(self, vnf_pkg_id, vnfd_id, vnf_id):
        """Inserts data in VNF_Instances collection in MongoDB

        :param vnf_pkg_id: local VNF Package ID
        :param vnfd_id: NFVO VNFD ID
        :param vnf_id: NFVO VNF ID
        :return: OK if succeeded, or ERROR and the message if not
        """
        try:
            data = self.db.VNF_Instances.insert_one({
                        'vnf_pkg_id': vnf_pkg_id,
                        'vnfd_id': vnfd_id,
                        'vnf_id': vnf_id
                        })
        except Exception as e:
            logger.error(e)
            return ERROR, e

        return OK, data.inserted_id

    def remove_vnf_instance(self, vnf_instance_id):
        """Removes a VNF Instance from the database

        :param vnf_instance_id: the local identifier for the MongoDB (i.e., the _id str value)
        :return: OK if succeeded, or ERROR and the message if not
        """
        try:
            self.db.VNF_Instances.delete_one({
                        '_id': ObjectId(vnf_instance_id)
                        })
        except Exception as e:
            logger.error(e)
            return ERROR, e

        return OK

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
            return OK, data
        except Exception as e:
            logger.error(e)
            return ERROR, e

    def insert_sfc_instance(self, vnf_instances, vnffgd_id, vnffg_id):
        """Inserts data in SFC_Instances collection in MongoDB

        :param vnf_instances: a list or dict with all vnf_instance_id stored in MongoDB
        :param vnffgd_id: NFVO VNFFGD ID
        :param vnffg_id: NFVO VNFFG ID
        :return: OK if succeeded, or ERROR and the message if not
        """
        try:
            data = self.db.SFC_Instances.insert_one({
                        'vnf_instances': vnf_instances,
                        'vnffgd_id': vnffgd_id,
                        'vnffg_id': vnffg_id
                        })
        except Exception as e:
            logger.error(e)
            return ERROR, e

        return OK, data.inserted_id

    def remove_sfc_instance(self, sfc_instance_id):
        """Removes a VNF Instance from the database

        :param sfc_instance_id: the local identifier for the MongoDB (i.e., the _id str value)
        :return: OK if succeeded, or ERROR and the message if not
        """
        try:
            data = self.db.SFC_Instances.delete_one({
                        '_id': ObjectId(sfc_instance_id)
                        })
        except Exception as e:
            logger.error(e)
            return ERROR, e

        if data.deleted_count == 1:
            return OK, data.deleted_count
        else:
            msg = 'SFC_Instance id %s not found!' % sfc_instance_id
            logger.warning(msg)
            return ERROR, msg

    def list_sfc_instances(self, sfc_instance_id=None, vnf_instances=None,
                           vnffgd_id=None, vnffg_id=None):
        """Returns a list of SFC Instances stored in MongoDB

        The function arguments are used to create the search criteria for the MongoDB.
        To get all SFC Instances stored in database just call this function without arguments.

        :param sfc_instance_id:
        :param vnf_instances: a list of VNF Instances
        :param vnffgd_id:
        :param vnffg_id:
        :return: A list of SFC Instances stored in database
        """
        criteria = {}
        if sfc_instance_id:
            criteria['_id'] = ObjectId(sfc_instance_id)
        if vnf_instances:
            criteria['vnf_instances'] = vnf_instances
        if vnffgd_id:
            criteria['vnffgd_id'] = vnffgd_id
        if vnffg_id:
            criteria['vnffg_id'] = vnffg_id

        try:
            sfc_instances = self.db.SFC_Instances.find(criteria)

            data = []
            for sfc in sfc_instances:
                if isinstance(sfc['_id'], ObjectId):
                    sfc['_id'] = str(sfc['_id'])
                data.append(sfc)
            return OK, data
        except Exception as e:
            logger.error(e)
            return ERROR, e


if __name__ == '__main__':
    import sys

    # Used for clean VNF_Instances and SFC_Instances performance tests database data
    if len(sys.argv) == 2 and sys.argv[1] == 'clean':
        database = DatabaseConnection()

        result = database.db.SFC_Instances.delete_many({})
        print('Removed %s SFC_Instances from database.' % result.deleted_count)

        result = database.db.VNF_Instances.delete_many({})
        print('Removed %s VNF_Instances from database.' % result.deleted_count)

    else:
        print('Usage: %s clean' % sys.argv[0])
