# nodecryptor: better wireguard for cilium

> [!WARNING] > This is experimental / works-for-the-author-grade software!  
> Tested with cilium 1.18.2

## Motivation

Cilium's [transparent wireguard encryption](https://docs.cilium.io/en/stable/security/network/encryption-wireguard/)
encrypts (most of) the traffic flowing between nodes of a cluster. While this
undoubtedly improves the security of your cluster network, it's current implementation
has two important limitations:

1) Cilium treats tunneling and encryption as orthogonal problems: With transparent
   encryption on, it will send vxlan tunnel traffic through the wg tunnel. That
   means very packet is encapsulated twice. Unless you need L2-connectivity between
   pods, this is wasteful not only in terms of compute, but more importantly you have
   the MTU-overhead of wg (60 byte) and vxlan (50 byte) instead of only the former.

2) Traffic between root network-namespaces of nodes can be encrypted (Node-to-Node
   encryption, considered beta) but it creates a bootstrapping-problem for
   control-plane nodes, which cilium solves by excluding control-plane nodes from
   Node-to-Node encryption. (See "The bootsrapping problem" below)

### Why these are relevant limitations:

Given that cilium currently does not support different MTUs for South-West and
North-South traffic, most setups will be working with an MTU of about 1500. That
ditching vxlan would remove a 3% overhead. The downside is that there is no more
L2-connectivity between pods on different nodes, but that is neither mandated by k8s,
nor a common requirement for cluster workloads.

In my experience, it is surprisingly easy to overlook that pods on different nodes
communicate using the root network namespace. While arguably all workloads should be
encrypted end-to-end and considering the cluster network trusted is perhaps a bit
foolish, it would be even more foolish to assume every organization has the
capabilities to implement encryption on all services. Especially in multi-cloud-clusters
overlooking these limitations of node-to-node encryption may mean transmitting
credentials
or other sensitive information in the clear. Setups without dedicated control-plane
nodes are especially susceptible to such "accidents".

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
fact that cilium doesn't already do that in the above description may arguably
be considered a bug.

The second issue, allowing node-to-node encryption on control-plane nodes is a bit
more tricky, since we need to solve the bootstrapping-problem. If you are not familiar  
with this bootstrapping problem is, I recommend going to the description below
and returning here.

Now, the way this PoC solves - or rather: avoids - the bootstrapping this problem is
that it exempts only the traffic necessary for bootstraping from encryption, rather
than the entire node. The key circumstance that allows us to do this is that the
kubernetes-api and etcd connections between control-plane nodes are usually already
encrypted!

Let's walk through how a control-plane node can connect to the wireguard network
even if the other nodes have an outdated public key set for it:

0) The node went offline, traffic from other nodes destined to it is encrypted with
   the old key, while this traffic will never be decrypted, it at least remains
   encrypted.
1) The node boots and connects to the kubernetes api and etcd (exempted from encryption)
2) The node can now update it's public key on the CiliumNode CRD with the new one.
3) The other nodes update their wireguard interface: full, encrypted connectivity is
   restored.

## Implementation

The key novelty is to selectively exempt traffic between nodes from wireguard: The
traffic that is required for bootstrapping and is encrypted by other means.
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

# On Control-plane nodes: Force bootstrap traffic through the main table:
# Reply traffic from exempted ports, the "more correct" solution here would be to 
# match the src address against the Nodes InternalIP rather than iif lo
ip rule add iif lo sport 2379-2380 lookup main priority 200
ip rule add iif lo sport 6443 lookup main priority 200

# For every $CONTROL_PLANE_NODE
# Ensure that exempted ports remain unencrypted
ip rule add to $CONTROL_PLANE_NODE dport 2379-2380  lookup main priority 200
ip rule add to $CONTROL_PLANE_NODE dport 6443 lookup main priority 200
# Now send the rest of traffic to the table that puts everything to the wg interface
ip rule add to $CONTROL_PLANE_NODE lookup 100 priority 201

# For every $WORKER_NODE
# Regular nodes don't need exemptions
ip rule add to $WORKER_NODE lookup 100 priority 201
```

## The bootstrap problem

## Limitations of the PoC / Further Ideas

It matches reply traffic from exempted ports using `iif lo`, matching for the
InternalIPs and ExternalIPs would be better.

It only distinguishes two types of nodes: control-plane and workers. A more general
mechanism would be a custom resource that specifies exempted ports (or other traffic
matchers) and label-selectors to support arbitrary exemptions on arbitrary subsets
of nodes.

