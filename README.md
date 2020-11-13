# Multi-SFC

Multi-SFC is a framework that allows the composition and management of the lifecycle of multiple segments of an SFC running across multiple clouds of different administrative domains orchestrated by multiple NFV platforms. The architecture of the Multi-SFC is compliant with the ETSI NFV-MANO standard and allows to interconnect SFC connects segments each on a specific cloud/domain/platform using tunnels implemented as VNFs. SFC compositions also can be done concurrently. In the current version, the Muti-SFC framework works with Tacker and OSM NFV orchestrators, both using OpenStack as their corresponding VIM.

## Prerequisites

Multi-SFC has the following software prerequisites:

* [Python 3](https://www.python.org/) - Python Language
* [OpenStack](https://www.openstack.org/) - OpenStack
* [Tacker](https://wiki.openstack.org/wiki/Tacker) - Tacker
* [OSM](https://osm.etsi.org/) - Open Source MANO
* [MongoDB](https://www.mongodb.com/) - NoSQL Database
* [Memcached](https://memcached.org/) - Distributed Memory Object Caching System
* [Docker](https://www.docker.com/) - (*Recommended*)
* [Apache](https://httpd.apache.org/) - HTTP Server (*Optional*)
* [Click-on-OSv](https://github.com/lmarcuzzo/click-on-osv) - Click-on-OSv (*Optional*)

## Installing

* OpenStack and Tacker can be installed either via *devstack*, or *kolla-ansible*, or system package manager. The implementation and testing was done using both *Train* and *Ussuri* versions.
* Open Source MANO (OSM) can be installed using the [OSM installation procedure](https://osm.etsi.org/docs/user-guide/03-installing-osm.html). Tested with OSM Release EIGHT. Should work with Release SIX and SEVEN as well.
* To install the Open Source Mano client locally, please follow the [osmclient installation procedure](https://osm.etsi.org/docs/user-guide/10-osm-client-commands-reference.html#installing-from-git-repo).
* The default configuration for MongoDB and Memcached should work with the framework.
* Another option to build and run the Multi-SFC is by using containers. Both [Dockerfile](Dockerfile) and [docker-compose.yaml](docker-compose.yaml) files are also provided in the repository. This is the smoothest and recommended option to build and run the Multi-SFC.

## Running

Before running the Multi-SFC, you must configure the corresponding clouds, domains, and orchestrators in the [domain-config.yaml](domain-config.yaml) file.

### Docker (*recommended option*)

**Server side**

```$ docker-compose up -d```

**Client side**

```$ docker run --rm --network host -v "$PWD":/app -it multisfc /app/client.py```

### Standalone (*for development*)

Start both ```mongod``` and ```memcached``` in the same machine the Multi-SFC server will run.

**Server side**

```./server```

**Client side**

```./client```

**VNF Packages**

* There are some VNF Packages in the [example](example) directory that can be onboarded using the Client Application.
* Generic VNF Packages were tested using [Bionic Ubuntu Cloud Images](https://cloud-images.ubuntu.com/bionic/)

## Contributing

Everyone is welcome to contribute to this project. Just check out the repository on a new branch and submit a pull request with your changes. Thank you!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

OSM Client files are licensed under the Apache License, Version 2.0. You may obtain a copy of the Apache License [here](http://www.apache.org/licenses/LICENSE-2.0).

## References

* A. Huff, G. Venancio, L. da C. Marcuzzo, V. F. Garcia, C. R. P. dos Santos and E. P. Duarte, "*A Holistic Approach to Define Service Chains Using Click-on-OSv on Different NFV Platforms*," 2018 IEEE Global Communications Conference (GLOBECOM), Abu Dhabi, United Arab Emirates, 2018, pp. 1-6, doi: 10.1109/GLOCOM.2018.8647418.

* A. Huff, G. Venancio, V. F. Garcia, and E. P. Duarte, "*Building Multi-domain Service Function Chains Based on Multiple NFV Orchestrators*," 6th IEEE Conference on Network Functions Virtualization and Software Defined Networking (IEEE NFV-SDN 2020), Madrid/Leganes, Spain, 2020. ( *Accepted Paper* )
