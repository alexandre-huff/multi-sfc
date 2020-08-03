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

    # We no longer need a Singleton, as we are using multi-processing instead of multi-threading in web server.
    # So all forked process in requests must open a new connection to the database
    #
    __instance = None

    # Singleton
    def __new__(cls, *args, **kwargs):
        if not cls.__instance:
            cls.__instance = super().__new__(cls)

        return cls.__instance

    def __init__(self):
        self.client = MongoClient(host='localhost', port=27017, maxPoolSize=200, serverSelectionTimeoutMS=5000)
        
        logger.debug("Opening database connection...")

        try:
            # this command is just used to verify the connection to the Mongo Database
            # see MongoClient() docs
            # also could be: self.client.server_info() which raises ServerSelectionTimeoutError
            self.client.admin.command('ismaster')
        except ConnectionFailure as e:
            logger.critical("MongoDB Server not available! %s", e)
            exit(1)

        self.db = self.client.multisfc

    def insert_vnf_package(self, category, vnfd_name, dir_id, vnf_type, domain_id, nfvo_id,
                           platform, description, tunnel):
        """
        Raises
        ------
            DatabaseException
        """
        try:
            res = self.db.catalog.insert_one({
                'category': category,
                'vnfd_name': vnfd_name,
                'dir_id': dir_id,
                'vnf_type': vnf_type,
                'domain_id': domain_id,
                'nfvo_id': nfvo_id,
                'platform': platform,
                'description': description,
                'tunnel': tunnel
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
            data = self.db.catalog.delete_one({
                        '_id': ObjectId(vnf_pkg_id)
                        })

            if not data.deleted_count:
                raise MultiSFCException('Failed on removing VNF Package %s from the database.' % vnf_pkg_id)

        except Exception as e:
            logger.error(e)
            raise DatabaseException(ERROR, str(e))

    def list_catalog(self, vnf_pkg_id=None, category=None, vnfd_name=None, dir_id=None, domain_id=None,
                     nfvo_id=None, platform=None, tunnel=None, criteria=None):
        """
        Retrieves a list of VNF Packages stored in database.

        Params are used to create "AND" queries.
        In order to user "OR" queries, use the criteria argument like this:
        { "$or": [{"domain_id": "domain1"}, {"domain_id": "ANY"}] }
        Another way to get an "OR" behavior is to use the "$in" with the arguments like this:
        domain_id={"$in": [value1, value2]}

        :param vnf_pkg_id:
        :param category:
        :param vnfd_name:
        :param dir_id:
        :param domain_id:
        :param nfvo_id:
        :param platform:
        :param tunnel:
        :param criteria: must be a dict

        :return: a list of vnf packages

        Raises
        -----
            DatabaseException
        """
        if not isinstance(criteria, dict):
            criteria = {}
        if vnf_pkg_id:
            criteria['_id'] = ObjectId(vnf_pkg_id)
        if category:
            criteria['category'] = category
        if vnfd_name:
            criteria['vnfd_name'] = vnfd_name
        if dir_id:
            criteria['dir_id'] = dir_id
        if domain_id:
            criteria['domain_id'] = domain_id
        if nfvo_id:
            criteria['nfvo_id'] = nfvo_id
        if platform:
            criteria['platform'] = platform
        if tunnel:
            criteria['tunnel'] = tunnel

        try:
            catalog = self.db.catalog.find(criteria)

            data = []
            for vnf in catalog:
                if isinstance(vnf['_id'], ObjectId):
                    vnf['_id'] = str(vnf['_id'])
                data.append(vnf)
            return data
        except Exception as e:
            logger.error(e)
            raise DatabaseException(ERROR, str(e))

    def insert_vnf_instance(self, vnf_pkg_id, domain_id, nfvo_id, vnfd_id, vnf_id):
        """Inserts data in VNF_Instances collection in MongoDB

        :param vnf_pkg_id: local VNF Package ID
        :param domain_id: the Domain ID in the domain catalog
        :param nfvo_id: the NFVO ID in the domain catalog
        :param vnfd_id: NFVO VNFD ID
        :param vnf_id: NFVO VNF ID

        Raises
        -----
            DatabaseException
        """
        try:
            data = self.db.vnf_instances.insert_one({
                        'vnf_pkg_id': vnf_pkg_id,
                        'domain_id': domain_id,
                        'nfvo_id': nfvo_id,
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
            res = self.db.vnf_instances.delete_one({
                        '_id': ObjectId(vnf_instance_id)
                        })
            if not res.deleted_count:
                raise MultiSFCException("VNF Instance not deleted from database!")

        except Exception as e:
            logger.error(e)
            raise DatabaseException(ERROR, str(e))

    def list_vnf_instances(self, vnf_instance_id=None, vnf_pkg_id=None,
                           domain_id=None, nfvo_id=None, vnfd_id=None, vnf_id=None):
        """Returns a list of VNF Instances stored in MongoDB

        The function arguments are used to create the search criteria for the MongoDB.
        To get all VNF Instances stored in database just call this function without arguments.

        :param vnf_instance_id:
        :param vnf_pkg_id:
        :param domain_id: the domain ID in domain catalog
        :param nfvo_id: the nfvo ID in domain catalog
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
        if domain_id:
            criteria['domain_id'] = domain_id
        if nfvo_id:
            criteria['nfvo_id'] = nfvo_id
        if vnfd_id:
            criteria['vnfd_id'] = vnfd_id
        if vnf_id:
            criteria['vnf_id'] = vnf_id

        try:
            vnf_instances = self.db.vnf_instances.find(criteria)

            data = []
            for vnf in vnf_instances:
                if isinstance(vnf['_id'], ObjectId):
                    vnf['_id'] = str(vnf['_id'])
                data.append(vnf)
            return data

        except Exception as e:
            logger.error(e)
            raise DatabaseException(ERROR, str(e))

    def insert_sfc_instance(self, sfc_name, multi_sfc_id, vnf_instances, nsd_id, ns_id, segment_name,
                            domain_id, nfvo_id):
        """Inserts data in SFC_Instances collection in MongoDB

        :param sfc_name: Name of the SFC
        :param multi_sfc_id: a multi-sfc unique identifier of all composed segments
        :param vnf_instances: a list or dict with all vnf_instance_id stored in MongoDB
        :param nsd_id: SFC Descriptor ID (NVFO VNFFGD ID or NSD ID)
        :param ns_id: SFC Instance ID (NFVO VNFFG or NS ID)
        :param segment_name: Name of the SFC Segment
        :param domain_id: The domain ID on which the SFC is running
        :param nfvo_id: The nfvo ID on which the SFC is running
        :return: the id of the inserted SFC

        Raises
        ------
            DatabaseException
        """
        try:
            data = self.db.sfc_instances.insert_one({
                'sfc_name': sfc_name,
                'multi_sfc_id': multi_sfc_id,
                'vnf_instances': vnf_instances,
                'nsd_id': nsd_id,
                'ns_id': ns_id,
                'segment_name': segment_name,
                'domain_id': domain_id,
                'nfvo_id': nfvo_id
                        })
            if not data.inserted_id:
                raise MultiSFCException("SFC Instance not inserted in database!")

        except Exception as e:
            logger.error(e)
            raise DatabaseException(ERROR, str(e))

        return str(data.inserted_id)

    def remove_sfc_instance(self, sfc_instance_id):
        """Removes a VNF Instance from the database

        :param sfc_instance_id: the local identifier for the MongoDB (i.e., the _id str value)

        Raises
        ------
            DatabaseException
        """
        try:
            data = self.db.sfc_instances.delete_one({
                        '_id': ObjectId(sfc_instance_id)
                        })
            if not data.deleted_count:
                raise MultiSFCException("SFC Instance not deleted from database!")

        except Exception as e:
            logger.error(e)
            raise DatabaseException(ERROR, str(e))

    def list_sfc_instances(self, sfc_instance_id=None, sfc_name=None, multi_sfc_id=None, vnf_instances=None,
                           nsd_id=None, ns_id=None, segment_name=None, domain_id=None, nfvo_id=None):
        """Returns a list of SFC Instances stored in MongoDB

        The function arguments are used to create the search criteria for the MongoDB.
        To get all SFC Instances stored in database just call this function without arguments.

        :param sfc_instance_id: the unique identifier generated by mongodb
        :param sfc_name:
        :param multi_sfc_id: the unique identifier of the multi-sfc instances
        :param vnf_instances: a list of vnfs
        :param nsd_id:
        :param ns_id:
        :param segment_name:
        :param domain_id:
        :param nfvo_id:
        :return: A list of SFC Instances stored in database

        Raises
        ------
            DatabaseException
        """
        criteria = {}
        if sfc_instance_id:
            criteria['_id'] = ObjectId(sfc_instance_id)
        if sfc_name:
            criteria['sfc_name'] = sfc_name
        if multi_sfc_id:
            criteria['multi_sfc_id'] = multi_sfc_id
        if segment_name:
            criteria['segment_name'] = segment_name
        if vnf_instances:
            criteria['vnf_instances'] = vnf_instances
        if nsd_id:
            criteria['nsd_id'] = nsd_id
        if ns_id:
            criteria['ns_id'] = ns_id
        if domain_id:
            criteria['domain_id'] = domain_id
        if nfvo_id:
            criteria['nfvo_id'] = nfvo_id

        try:
            sfc_instances = self.db.sfc_instances.find(criteria)

            data = []
            for sfc in sfc_instances:
                if isinstance(sfc['_id'], ObjectId):
                    sfc['_id'] = str(sfc['_id'])
                data.append(sfc)
            return data

        except Exception as e:
            logger.error(e)
            raise DatabaseException(ERROR, str(e))

    def update_sfc_instance(self, sfc_instance_id, sfc_name=None, multi_sfc_id=None, vnf_instances=None,
                            nsd_id=None, ns_id=None, segment_name=None, domain_id=None, nfvo_id=None, routing=None):
        """Returns a list of SFC Instances stored in MongoDB

        The function arguments are used to create the search criteria for the MongoDB.
        To get all SFC Instances stored in database just call this function without arguments.

        :param sfc_instance_id: the unique identifier generated by mongodb
        :param sfc_name:
        :param multi_sfc_id: the unique identifier of the multi-sfc instances
        :param vnf_instances: a list of vnfs
        :param nsd_id:
        :param ns_id:
        :param segment_name:
        :param domain_id:
        :param nfvo_id:
        :param routing: information about a route in a router, must be a **dict** containing the following router
            information: (*subnet_cidr, destination, next_hop*)
        :return: A list of SFC Instances stored in database

        Raises
        ------
            DatabaseException
        """
        update_data = {}
        if sfc_name:
            update_data['sfc_name'] = sfc_name
        if multi_sfc_id:
            update_data['multi_sfc_id'] = multi_sfc_id
        if segment_name:
            update_data['segment_name'] = segment_name
        if vnf_instances:
            update_data['vnf_instances'] = vnf_instances
        if nsd_id:
            update_data['nsd_id'] = nsd_id
        if ns_id:
            update_data['ns_id'] = ns_id
        if domain_id:
            update_data['domain_id'] = domain_id
        if nfvo_id:
            update_data['nfvo_id'] = nfvo_id
        if routing:
            update_data['routing'] = routing

        try:
            data = self.db.sfc_instances.update_one({'_id': ObjectId(sfc_instance_id)},
                                                    {"$set": update_data})

            if not data.modified_count:
                logger.warning("SFC Instance %s not updated in database! update_data: %s",
                               sfc_instance_id, update_data)

        except Exception as e:
            logger.error(e)
            raise DatabaseException(ERROR, str(e))


if __name__ == '__main__':
    import sys

    # Used to clean VNF_Instances, SFC_Instances, and SFC_Segments performance tests database data
    if len(sys.argv) == 2 and sys.argv[1] == 'clean':
        database = DatabaseConnection()

        result = database.db.sfc_segments.delete_many({})
        print('Removed %s SFC_Segments from database.' % result.deleted_count)

        result = database.db.sfc_instances.delete_many({})
        print('Removed %s SFC_Instances from database.' % result.deleted_count)

        result = database.db.vnf_instances.delete_many({})
        print('Removed %s VNF_Instances from database.' % result.deleted_count)

    else:
        print('Usage: %s clean' % sys.argv[0])
