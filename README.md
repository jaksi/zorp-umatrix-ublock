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
### Proxy properties
 * ```delete_session_cookies```: Discards session cookies after the time specified in ```unused_session_cookie_lifetime``` has passed since their last use
 * ```unused_session_cookie_lifetime```: See ```delete_session_cookies```
 * ```block_hyperlink_auditing```: Blocks [hyperlink auditing](https://html.spec.whatwg.org/multipage/semantics.html#hyperlink-auditing) requests
 * ```user_agents```: A list of strings to choose from when spoofing the User-Agent header of requests
 * ```user_agent_interval```: The time for which a User-Agent is used for a client, after this, a new User-Agent is chosen
 * ```enable_matrix```: Enables the matrix filtering engine, described later
 * ```matrix_file```: The configuration of file of the matrix engine. You can use the [included converter](matrix2proxy) to convert existing uMatrix rules.
 * ```enable_abp```: Enables the partial Adblock Plus engine, described later
 * ```abp_filter```: The Adblock Plus filter to use
