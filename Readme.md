# nodecryptor: better wireguard for cilium

> [!WARNING] > This is experimental / works-for-the-author-grade software!  
> Tested with cilium 1.18.2

## Motivation

Cilium's [transparent wireguard encryption](https://docs.cilium.io/en/stable/security/network/encryption-wireguard/)
encrypts (most of) the traffic flowing between nodes of a cluster. While this
undoubtedly improves the security of your cluster network, its current implementation
has two important limitations:

1) Cilium treats tunneling and encryption as orthogonal problems: With transparent
   encryption on, it will send vxlan tunnel traffic through the wg tunnel. That
   means every packet is encapsulated twice. Unless you need L2-connectivity between
   pods, this is wasteful not only in terms of compute, but more importantly you have
   the MTU-overhead of wg (60 byte) and vxlan (50 byte) instead of only the former.

2) Traffic between root network-namespaces of nodes can be encrypted (Node-to-Node
   encryption, considered beta) but it creates a bootstrapping-problem, which cilium
   solves by excluding control-plane nodes from Node-to-Node encryption.
   (See "The bootsrapping problem" below)

### Why these are relevant limitations:

Given that cilium currently does not support different MTUs for South-West and
North-South traffic, most setups will be working with an MTU of about 1500. That means
ditching vxlan would remove a 3% overhead. The downside is that there is no more
L2-connectivity between pods on different nodes, but that is neither mandated by k8s,
nor a common requirement for cluster workloads.

In my experience, it is surprisingly easy to overlook that pods on different nodes
communicate using the root network namespace. While arguably all workloads should be
encrypted end-to-end and considering the cluster network trusted is perhaps a bit
foolish, it would be even more foolish to assume every organization has the
capabilities to implement encryption on all services. Especially in multi-cloud
clusters, overlooking these limitations of node-to-node encryption may entail
transmitting credentials or other sensitive information in the clear. Setups without
dedicated control-plane nodes are especially susceptible to such "accidents".

## Approach

The first issue is already almost entirely solved by setting cilium's
`routingMode` to `native`, configuring `ipv4NativeRoutingCIDR` to cover the entire
pod-cidr and simultaneously enabling encryption with `type: wireguard`. With these
settings, pod-to-pod traffic is sent through `cilium_wg0`.

However, traffic between your nodes' root namespaces and remote pods, as well as
node-to-node traffic will be treated like north-south traffic and simply go through the
main routing table and thus likely the default interface, unencrypted. This issue is
rather easy to fix, especially since cilium already configures all relevant ips
as allowed ips on the peers of the `cilium_wg0` interface. We merely need to route
traffic between pods and remote nodes (and vice versa) through that interface. The
fact that cilium doesn't already do that in the above described configuration may
arguably be considered a bug.

The second issue, allowing node-to-node encryption on control-plane nodes is a bit
more tricky, since we need to solve the bootstrapping-problem. If you are not familiar
with this bootstrapping problem, I recommend going to the description below and
returning here.

The way this PoC solves - or rather avoids - this bootstrapping problem is that it
exempts only the traffic necessary for bootstraping from encryption, rather
than the entire control-plane node. The key circumstance that allows us to do this is
that the kubernetes-api and etcd connections between control-plane nodes are usually
already encrypted!

Let's walk through how a control-plane node can connect to the wireguard network
even if the other nodes have an outdated public key set for it:

0) The node went offline, inbound traffic from other nodes destined is encrypted
   with the old key, while this traffic will never be decrypted, it at least remains
   encrypted.
1) The node boots and connects to the kubernetes api and etcd (exempted from encryption)
2) The node can now update it's public key on the CiliumNode CRD with the new one.
3) The other nodes update their wireguard interface: Full encrypted connectivity is
   restored.

## Implementation

The key novelty is to selectively exempt traffic between nodes from wireguard: The
traffic that is required for bootstrapping (and is hopefully encrypted by other means).
This can be achieved using Linux's policy based routing facilities (ip rule) and
certainly also with BPF in ciliums data-path.

I will illustrate this with control-plane nodes that run kube api on port 6443 and
etcd on 2379 and 2380. The shell script below illustrates what nodecryptor does:

```sh
# Ensure traffic already encrypted by wg goes through the main routing table
# cilium configures the cilium_wg0 interface to emit packets with the 0xe00 mark
ip rule add fwmark 0xe00 lookup main priority 0

# Add a routing table (id 100) that sends everything through the wg interface
ip route add default dev cilium_wg0 scope link table 100

# On control-plane nodes: Force bootstrap reply traffic through the main table
ip rule add iif lo sport 2379-2380 lookup main priority 200
ip rule add iif lo sport 6443 lookup main priority 200

# For every $CONTROL_PLANE_NODE
# Ensure that exempted destinations remain unencrypted
ip rule add to $CONTROL_PLANE_NODE dport 2379-2380  lookup main priority 200
ip rule add to $CONTROL_PLANE_NODE dport 6443 lookup main priority 200
# Now send the rest of traffic to the table that puts everything to the wg interface
ip rule add to $CONTROL_PLANE_NODE lookup 100 priority 201

# For every $WORKER_NODE
# Regular nodes don't need exemptions
ip rule add to $WORKER_NODE lookup 100 priority 201
```

## The bootstrap problem

The bootstrap problem for ciliums wireguard encryption arises when a node reboots, or
more specifically: When its `cilium_wg0` interface is taken down. When the cilium
agent sets up the interface, it configures the private key and communicates the public
key to other nodes via the `CiliumNode` resource. Crucially, the private key is not
persisted anywhere. This can create the following situation:

1) A node joins the cluster
2) It creates the interface, configures the keypair and publishes the public key
3) If Node-To-Node encryption is enabled, all other nodes start encrypting traffic
   headed for the new node
4) When the node reboots, the private key is lost
5) Now when the node tries to reconnect to the control-plane, reply-packets are
   encrypted, but it can't decrypt them.

To avoid this problem, cilium exempts control-plane nodes from node-to-node encryption.

## Usage

```
Usage of ./nodeCryptor:
  -control-plane-exempt-ports string
    	Comma-separated list of ports/ranges to exempt from encryption for control-plane nodes (default "2379-2380,6443")
  -health-probe-bind-address string
    	Health probe bind address (default ":8083")
  -kubeconfig string
    	Paths to a kubeconfig. Only required if out-of-cluster.
  -metrics-server-bind-address string
    	Metrics server bind address (default ":8084")
  -node-name string
    	Name of the node (falls back to NODE_NAME env var)
  -noop-route string
    	Add a noop route to the specified destination
```

You can use the kubernetes manifests in [./k8s](./k8s) as reference. The
`netshot-daemonset` is just for troubleshooting. Please note the below:

## Why the noop route?

In all my testing I have observed that cluster traffic will not be affected by ip rules
if there isn't at least one non-default route in the main table. I suspect that cilium
will use the faster `bpf_rediret` if there is no "interesting" routing information,
but fails to consider ip rules for that. If specified, it will essentially perform:

```sh
ip link add noop type dummy
ip link set noop up
ip route add $YOUR_NOOP_TARGET dev noop
```

You should specify some private ipv4 that doesn't overlap with your cluster network.

## Limitations of the PoC / further ideas

It only matches exempted traffic based on ports, in principle, other traffic
matching rules might also be interesting.

It matches exempted reply traffic from using `iif lo`, matching for the local
InternalIPs and ExternalIPs as source ips would be better.

It only distinguishes two types of nodes: control-plane and workers. A more general
mechanism would be a custom resource that specifies exempted traffic and
node label-selectors to support arbitrary exemptions on arbitrary nodes.

No IPv6.

This is my first go project, it might contain weird code. :3

# AI Disclaimer

This is my first go project, I used claude code for some tasks to help me write
idiomatic code. I double-checked generated code and ended up simplifying / rewriting
almost all of it. The core logic of the reconciler I wrote from scratch.
