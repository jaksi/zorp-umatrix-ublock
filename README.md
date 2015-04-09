# zorp-umatrix-ublock
### Creating an environment
 * install LXC
 * create a bridge interface called br0, and attach your network interface to it
 * edit create_env and set the name and IP address of the container
 * run create_vm as root

You should now have an HTTP proxy listening on the specified IP on port 8080.
