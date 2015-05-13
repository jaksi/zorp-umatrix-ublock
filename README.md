# zorp-umatrix-ublock
A content filtering proxy for [Zorp](https://github.com/balabit/zorp), implementing features from [uMatrix](https://github.com/gorhill/uMatrix) and [uBlock](https://github.com/gorhill/uBlock).
## Creating a container to test the proxy
### Requirements
 * [LXC](https://github.com/lxc/lxc)
 * The kernel-related requirements of systemd described [here](http://cgit.freedesktop.org/systemd/systemd/tree/README), since the container uses Fedora 21

### Steps
 * Run ```create_vm``` as root
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
 * ```enable_abp```: Enables the experimental and partial Adblock Plus engine, described later
 * ```abp_filter```: The Adblock Plus filter to use

## The matrix filtering engine
For a general idea on how this works, read the [HTTP Switchboard Wiki](https://github.com/gorhill/httpswitchboard/wiki/Net-request-filtering:-overview#matrix-filtering). This implementation aims to give a result as close as possible to that of HTTP Switchboard and uMatrix.
### Unimplemented features
#### Rule scopes
There is no reliable way to tell the source host of a request, without generating lots of false positives.

#### 1st party requests
As with rule scopes, there is no way to tell the source host of the request.

#### plugin, XHR and frame
There is no reliable way to get the initiator of a request.

### Additional features compared to uMatrix
#### Internet media types
In addition to the implemented rule types of uMatrix (cookie, css, image, script, other), any partial or full Internet media type can be set as a type.

For example, ```application/xml``` will match on responses with that type, and ```audio``` will match on any resource with the top-level type of ```audio``` (```audio/opus```, ```audio/vorbis```, etc.).

#### Multiple hostnames and types
To make the configuration more similar to the visual representation of uMatrix and easier to modify, a rule can have multiple hostnames and types.

### Matrix configuration
The configuration is stored in a JSON object with two keys. The ```allow``` key represents the ```all``` cell of uMatrix, and the ```rules``` key stores the list of the actual rules.

Each rule can have three keys. The ```hostname``` key stores a list of hostnames and the ```type``` key stores a list of types. At least one of these keys have to be present. The ```allow``` key stores the result of the rule.

The [example matrix configuration](examples/matrix.json) blocks images and audio from example.com, blocks all cookies except from example.org, and allows everything else.

## Adblock Plus engine
The Adblock Plus filtering engine is still in a proof of concept state, since it's painfully slow with commonly used filters.
### Unimplemented features
#### Checksum calculation
#### Type options
The following types (and their inverse counterparts) are virtually impossible to implement for reasons discussed in the matrix filtering section:
 * ```object```
 * ```xmlhttprequest```
 * ```object-subrequest```
 * ```subdocument```
 * ```elemhide```
 * ```other```

#### ```third-party``` and ```~third-party``` options
For reasons described in the matrix filtering section, this won't be implemented.
#### ```sitekey``` option
#### ```collapse``` option
#### ```donottrack``` option
#### All element hiding rules
Filtering arbitrary HTML content on a proxy isn't trivial, since any HTML code can be injected using JavaScript. Browser extensions can rely on the browsers engine to execute all JavaScript code before filtering HTML elements, but the same can't be done on a proxy.

Consider the following code:
```javascript
document.write('<div class="annoying-ad">Nasty JavaScript ad</div>');
```
Blocking elements like that would require parsing the JavaScript code on the proxy. Keep in mind that the code injecting the HTML elements could be far more obfuscated.

For this reason, element hiding rules are not implemented in the proxy, but since most sites use an easily recognizaable domain for serving ads, this is not that big of a deal.
