# Multi-SFC

Multi-SFC is a framework for composing and managing the lifecycle of multiple SFC segments distributed on different clouds/domains/NFVOs. This framework was specified according to the ETSI NFV-MANO architecture and aims to simplify the composition and lifecycle management of SFCs with multiple segments on multiple NFV platforms. SFC compositions also can be done concurrently. Currently, the Muti-SFC framework works with Tacker and OSM NFV orchestrators, both using OpenStack as their corresponding VIM.

## Prerequisites

Multi-SFC has the following software prerequisites:

* [OpenStack](https://www.openstack.org/) - OpenStack
* [Tacker](https://wiki.openstack.org/wiki/Tacker) - Tacker
* [OSM](https://osm.etsi.org/wikipub/index.php/OSM_Release_FOUR) - OSM Release FOUR
* [MongoDB](https://www.mongodb.com/) - Database
* [Memcached](https://memcached.org/) - Distributed Memory Object Caching System
* [Apache](https://httpd.apache.org/) - HTTP Server (*Optional*)
* [Click-on-OSv](https://github.com/lmarcuzzo/click-on-osv) - Click-on-OSv (*Optional*)

## Installing

* OpenStack and Tacker can be installed via *devstack*. The implementation and testing was done using both *Train* and *Ussuri* versions.
* Open Source MANO (OSM) can be installed using the *Default installation procedure*. Please, check out the above OSM link.
* Default configuration for MongoDB and Memcached should work with the framework.

## Running

**Server Side**

```./server```

**Client**

```./client```

* There are a few VNF Packages in the [example](example) directory that can be used as *VNF Package* in Client Application.
* Generic VNF Packages were tested using [Bionic Ubuntu Cloud Images](https://cloud-images.ubuntu.com/bionic/)

## Built using

* [Python 3](https://www.python.org/)

## Reference


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

OSM Client files are licensed under the Apache License, Version 2.0. You may obtain a copy of the Apache License [here](http://www.apache.org/licenses/LICENSE-2.0).

