use crate::network::{INTERNET_NETWORK_NAME, Network, SubNetwork};

use nix::{
    mount::{MntFlags, umount2},
    net::if_::if_nametoindex,
    sched::{CloneFlags, setns},
};
use rtnetlink::{
    Handle, LinkBridge, LinkUnspec, LinkVeth, NetworkNamespace, RouteMessageBuilder,
    packet_route::route::{RouteScope, RouteType},
};
use std::{fs::File, net::Ipv4Addr, os::fd::AsRawFd, thread};

/// Router through which all the traffic goes, to generate the final PCAP
pub const ROUTER_NS: &str = "fosr-router";
/// Catch-all namespace for the anonymous Internet (random public IPs)
pub const INTERNET_NS: &str = "fosr-internet";

const NETNS_DIR: &str = "/run/netns";
/// Prefix of every namespace of the lab
const PREFIX: &str = "fosr-";
/// Next hop of the point-to-point links of the known Internet hosts
const LINK_GW: Ipv4Addr = Ipv4Addr::new(169, 254, 0, 1);
/// Router side and Internet side of the router <-> fosr-internet link
const INET_ROUTER: Ipv4Addr = Ipv4Addr::new(169, 254, 1, 1);
const INET_PEER: Ipv4Addr = Ipv4Addr::new(169, 254, 1, 2);
const INET_PREFIX: u8 = 30;
/// Veth names of the router <-> fosr-internet link
const VR_INET: &str = "vr-inet";
const VH_INET: &str = "vh-inet";
/// Id of the kernel "local" routing table
const RT_TABLE_LOCAL: u32 = 255;

/// Namespace of an IP of the topology
pub fn ns_name(ip: &Ipv4Addr) -> String {
    format!("{PREFIX}{ip}")
}

/// Router end and host end of the veth of an IP (interface names must stay under 16 chars)
fn veth_names(ip: &Ipv4Addr) -> (String, String) {
    let x = u32::from(*ip);
    (format!("vr{x:08x}"), format!("vh{x:08x}"))
}

/// The gateway of a subnet is its first address
fn gateway(sub: &SubNetwork) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(sub.subnet) + 1)
}

/// Open the file of a namespace, to give it to `setns`
pub fn open_ns(ns: &str) -> Result<File, String> {
    File::open(format!("{NETNS_DIR}/{ns}")).map_err(|e| format!("namespace {ns}: {e}"))
}

/// Move the calling thread (only this one) into a namespace
fn enter(ns: &str) -> Result<(), String> {
    setns(open_ns(ns)?, CloneFlags::CLONE_NEWNET).map_err(|e| e.to_string())
}

/// Open a netlink connection in the namespace of the calling thread
fn connect() -> Result<Handle, String> {
    let (conn, handle, _) = rtnetlink::new_connection().map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    Ok(handle)
}

/// Index of an interface, looked up in the namespace of the calling thread
fn ifindex(name: &str) -> Result<u32, String> {
    if_nametoindex(name).map_err(|e| format!("interface {name}: {e}"))
}

/// Delete a namespace, like `ip netns del`. Plain sync calls, so it can be used in `Drop`.
fn delete_ns(ns: &str) {
    let path = format!("{NETNS_DIR}/{ns}");
    let _ = umount2(path.as_str(), MntFlags::MNT_DETACH);
    if let Err(e) = std::fs::remove_file(&path) {
        log::warn!("Could not delete namespace {ns}: {e}");
    }
}

/// Deletes the namespaces created by `Network::create_netns` when dropped. Must be used otherwise the lab gets deleted instantly
#[must_use]
pub struct NetnsGuard {
    /// Router last: deleting it also removes the bridges and the router ends of the veths
    namespaces: Vec<String>,
}

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        for ns in &self.namespaces {
            delete_ns(ns);
        }
    }
}

/// Create a namespace and a veth from the router to it. `vr` stays in the router, `vh` is moved
/// into the namespace. Both are still down.
async fn plug(router: &Handle, ns: &str, vr: &str, vh: &str) -> Result<(), String> {
    NetworkNamespace::add(ns).await.map_err(|e| e.to_string())?;
    router
        .link()
        .add(LinkVeth::new(vr, vh).build())
        .execute()
        .await
        .map_err(|e| e.to_string())?;
    let target = open_ns(ns)?;
    router
        .link()
        .set(
            LinkUnspec::new_with_name(vh)
                .setns_by_fd(target.as_raw_fd())
                .build(),
        )
        .execute()
        .await
        .map_err(|e| e.to_string())
}

/// Give an address to `dev` and set it up. The thread must be in the namespace of `handle`.
async fn addr_up(handle: &Handle, dev: &str, ip: Ipv4Addr, prefix: u8) -> Result<u32, String> {
    let idx = ifindex(dev)?;
    handle
        .address()
        .add(idx, ip.into(), prefix)
        .execute()
        .await
        .map_err(|e| e.to_string())?;
    handle
        .link()
        .set(LinkUnspec::new_with_index(idx).up().build())
        .execute()
        .await
        .map_err(|e| e.to_string())?;
    Ok(idx)
}

impl Network {
    /// Every namespace of the lab, router last
    fn namespaces(&self) -> Vec<String> {
        let mut namespaces: Vec<String> = self.all_ips.iter().map(ns_name).collect();
        if self.has_internet_access {
            namespaces.push(INTERNET_NS.into());
        }
        namespaces.push(ROUTER_NS.into());
        namespaces
    }

    /// Create the router namespace, one bridge per subnet and one namespace per IP.
    /// The namespaces are deleted when the returned guard is dropped.
    pub fn create_netns(&self) -> Result<NetnsGuard, String> {
        // 0. Remove leftovers of a previous run (maybe with another topology)
        if let Ok(entries) = std::fs::read_dir(NETNS_DIR) {
            for name in entries
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
            {
                if name.starts_with(PREFIX) {
                    log::info!("Deleting leftover namespace {name}");
                    delete_ns(&name);
                }
            }
        }

        // created first, so that an error below cleans up what was already made
        let guard = NetnsGuard {
            namespaces: self.namespaces(),
        };
        // setns only moves the current thread, so we build the lab in a thread that ends right after
        thread::scope(|s| {
            thread::Builder::new()
                .name("netns-setup".into())
                .spawn_scoped(s, || self.build_netns())
                .map_err(|e| e.to_string())?
                .join()
                .map_err(|_| "netns setup thread panicked".to_string())?
        })?;
        Ok(guard)
    }

    /// Move the calling thread (only this one) into the namespace of `ip`
    pub fn enter_ns(&self, ip: &Ipv4Addr) -> Result<(), String> {
        enter(&ns_name(ip))
    }

    fn build_netns(&self) -> Result<(), String> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .map_err(|e| e.to_string())?;

        rt.block_on(async {
            // 1. Router: forwards everything, and is where the traffic is captured
            NetworkNamespace::add(ROUTER_NS)
                .await
                .map_err(|e| e.to_string())?;
            enter(ROUTER_NS)?;
            let router = connect()?;
            std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").map_err(|e| e.to_string())?;

            let local_subnets = self
                .networks
                .iter()
                .filter(|n| n.name != INTERNET_NETWORK_NAME);
            for (s, subnet) in local_subnets.clone().enumerate() {
                // 2. Create one bridge for each subnet, with the gateway IP
                let br = format!("br{s}");
                router
                    .link()
                    .add(LinkBridge::new(&br).build())
                    .execute()
                    .await
                    .map_err(|e| e.to_string())?;
                let br_idx = ifindex(&br)?;
                router
                    .address()
                    .add(br_idx, gateway(subnet).into(), subnet.mask)
                    .execute()
                    .await
                    .map_err(|e| e.to_string())?;

                for ip in subnet.hosts.iter().flat_map(|h| h.get_ip_addr()) {
                    // 3. Create a namespace for each IP, linked to the router by a veth
                    let ns = ns_name(&ip);
                    let (vr, vh) = veth_names(&ip);
                    plug(&router, &ns, &vr, &vh).await?;

                    // 4. Plug the router end into the bridge
                    router
                        .link()
                        .set(
                            LinkUnspec::new_with_name(&vr)
                                .controller(br_idx)
                                .up()
                                .build(),
                        )
                        .execute()
                        .await
                        .map_err(|e| e.to_string())?;

                    // 5. Configure the host: IP, interface up, default route to the gateway
                    enter(&ns)?;
                    let host = connect()?;
                    addr_up(&host, &vh, ip, subnet.mask).await?;
                    host.route()
                        .add(
                            RouteMessageBuilder::<Ipv4Addr>::new()
                                .gateway(gateway(subnet))
                                .build(),
                        )
                        .execute()
                        .await
                        .map_err(|e| e.to_string())?;
                    enter(ROUTER_NS)?; // back, so that ifindex() finds the router interfaces
                }
            }

            // 6. Known Internet hosts: no common subnet, so one point-to-point link each
            let internet_ips: Vec<Ipv4Addr> = self
                .networks
                .iter()
                .filter(|n| n.name == INTERNET_NETWORK_NAME)
                .flat_map(|n| &n.hosts)
                .flat_map(|h| h.get_ip_addr())
                .collect();
            for ip in internet_ips {
                let ns = ns_name(&ip);
                let (vr, vh) = veth_names(&ip);
                plug(&router, &ns, &vr, &vh).await?;
                // several vr can share LINK_GW/32: each host sees its own copy of the gateway
                let vr_idx = addr_up(&router, &vr, LINK_GW, 32).await?;
                router
                    .route()
                    .add(
                        RouteMessageBuilder::<Ipv4Addr>::new()
                            .destination_prefix(ip, 32)
                            .output_interface(vr_idx)
                            .scope(RouteScope::Link)
                            .build(),
                    )
                    .execute()
                    .await
                    .map_err(|e| e.to_string())?;

                enter(&ns)?;
                let host = connect()?;
                let vh_idx = addr_up(&host, &vh, ip, 32).await?;
                // onlink: LINK_GW is reachable on vh even though it is not in a subnet of the host
                host.route()
                    .add(
                        RouteMessageBuilder::<Ipv4Addr>::new()
                            .gateway(LINK_GW)
                            .output_interface(vh_idx)
                            .onlink()
                            .build(),
                    )
                    .execute()
                    .await
                    .map_err(|e| e.to_string())?;
                enter(ROUTER_NS)?;
            }

            // 7. Anonymous Internet: one namespace that accepts every IP not routed elsewhere
            if self.has_internet_access {
                plug(&router, INTERNET_NS, VR_INET, VH_INET).await?;
                addr_up(&router, VR_INET, INET_ROUTER, INET_PREFIX).await?;

                enter(INTERNET_NS)?;
                let inet = connect()?;
                inet.link()
                    .set(LinkUnspec::new_with_name("lo").up().build())
                    .execute()
                    .await
                    .map_err(|e| e.to_string())?;
                addr_up(&inet, VH_INET, INET_PEER, INET_PREFIX).await?;
                inet.route()
                    .add(
                        RouteMessageBuilder::<Ipv4Addr>::new()
                            .gateway(INET_ROUTER)
                            .build(),
                    )
                    .execute()
                    .await
                    .map_err(|e| e.to_string())?;
                // every destination is local (AnyIP)...
                inet.route()
                    .add(
                        RouteMessageBuilder::<Ipv4Addr>::new()
                            .kind(RouteType::Local)
                            .table_id(RT_TABLE_LOCAL)
                            .scope(RouteScope::Host)
                            .output_interface(ifindex("lo")?)
                            .build(),
                    )
                    .execute()
                    .await
                    .map_err(|e| e.to_string())?;
                // ...except the local subnets and the router link, so that replies go back out
                let link_net =
                    Ipv4Addr::from(u32::from(INET_ROUTER) & !((1 << (32 - INET_PREFIX)) - 1));
                let throws = local_subnets
                    .map(|n| (n.subnet, n.mask))
                    .chain([(link_net, INET_PREFIX)]);
                for (subnet, mask) in throws {
                    inet.route()
                        .add(
                            RouteMessageBuilder::<Ipv4Addr>::new()
                                .destination_prefix(subnet, mask)
                                .kind(RouteType::Throw)
                                .table_id(RT_TABLE_LOCAL)
                                .build(),
                        )
                        .execute()
                        .await
                        .map_err(|e| e.to_string())?;
                }

                // last: everything the router does not know goes to the Internet
                enter(ROUTER_NS)?;
                router
                    .route()
                    .add(
                        RouteMessageBuilder::<Ipv4Addr>::new()
                            .gateway(INET_PEER)
                            .build(),
                    )
                    .execute()
                    .await
                    .map_err(|e| e.to_string())?;
            }
            Ok(())
        })
    }
}
