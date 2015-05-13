# zorp-umatrix-ublock
A content filtering proxy for [Zorp](https://github.com/balabit/zorp), implementing features from [uMatrix](https://github.com/gorhill/uMatrix) and [uBlock](https://github.com/gorhill/uBlock).
## Creating a container to test the proxy
### Requirements
 * LXC with the fedora template and its possible requirements
 * Linux >= 3.7, since the container is based on Fedora 21, which uses systemd

### Steps
 * Run create_vm as root
 * Set your HTTP proxy to ```localhost:8080``` (replace ```localhost``` with the host you ran the script on)

## Configuration
An [example configuration](examples/policy_uProxy.py) is located in the examples directory.
