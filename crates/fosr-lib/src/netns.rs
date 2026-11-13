use crate::network::{Host, HostType, INTERNET_NETWORK_NAME, Network, SubNetwork};

use nix::{
    mount::{MntFlags, umount2},
    net::if_::if_nametoindex,
    sched::{CloneFlags, setns},
    unistd::geteuid,
};
use rtnetlink::{
    Handle, LinkBridge, LinkUnspec, LinkVeth, NetworkNamespace, RouteMessageBuilder,
    packet_route::route::{RouteScope, RouteType},
};
use std::{
    collections::HashSet,
    fs::File,
    net::Ipv4Addr,
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Child, Command},
    sync::atomic::{AtomicBool, Ordering},
    thread,
};

/// Router through which all the traffic goes, to generate the final PCAP
pub const ROUTER_NS: &str = "fosr-router";
/// Catch-all namespace for the anonymous Internet (random public IPs)
pub const INTERNET_NS: &str = "fosr-internet";

const NETNS_DIR: &str = "/run/netns";
/// Prefix of every namespace of the lab
const PREFIX: &str = "fosr-";
/// Next hop of the point-to-point links (IPs outside every subnet)
const LINK_GW: Ipv4Addr = Ipv4Addr::new(169, 254, 0, 1);
/// Router side and Internet side of the router <-> fosr-internet link
const INET_ROUTER: Ipv4Addr = Ipv4Addr::new(169, 254, 1, 1);
const INET_PEER: Ipv4Addr = Ipv4Addr::new(169, 254, 1, 2);
const INET_PREFIX: u8 = 30;
/// Veth names of the router <-> fosr-internet link
const VR_INET: &str = "vr-inet";
const VH_INET: &str = "vh-inet";

/// Whether this process has a lab, for the Ctrl-C handler
static LAB_ALIVE: AtomicBool = AtomicBool::new(false);

/// Namespace of a host, named after its first IP
fn host_ns(host: &Host) -> String {
    format!("{PREFIX}{}", host.interfaces[0].ip_addr)
}

/// Router end and host end of the veth of an IP (interface names must stay under 16 chars)
fn veth_names(ip: &Ipv4Addr) -> (String, String) {
    let x = u32::from(*ip);
    (format!("vr{x:08x}"), format!("vh{x:08x}"))
}

/// Netmask of a subnet, as an integer
fn netmask(sub: &SubNetwork) -> u32 {
    u32::MAX.checked_shl(32 - sub.mask as u32).unwrap_or(0)
}

/// Whether `ip` is inside `sub`
fn contains(sub: &SubNetwork, ip: &Ipv4Addr) -> bool {
    u32::from(*ip) & netmask(sub) == u32::from(sub.subnet) & netmask(sub)
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

/// Delete every namespace of the lab, even the ones of a previous run
fn delete_all_netns() {
    let Ok(entries) = std::fs::read_dir(NETNS_DIR) else {
        return;
    };
    for name in entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
    {
        if name.starts_with(PREFIX) {
            log::info!("Deleting namespace {name}");
            delete_ns(&name);
        }
    }
}

/// Delete the lab of this process, if any. For the exits that skip `Drop` (Ctrl-C)
pub fn delete_lab_on_exit() {
    if LAB_ALIVE.swap(false, Ordering::Relaxed) {
        delete_all_netns();
    }
}

/// Start `cmd` inside the namespace `ns`
pub fn spawn_in(ns: &str, cmd: &mut Command) -> Result<Child, String> {
    // opened before the fork: only `setns` runs in the child before exec
    let f = open_ns(ns)?;
    // SAFETY: setns is a plain syscall, it doesn't allocate nor take locks
    unsafe {
        cmd.pre_exec(move || setns(&f, CloneFlags::CLONE_NEWNET).map_err(std::io::Error::from));
    }
    cmd.spawn()
        .map_err(|e| format!("Cannot start {:?}: {e}", cmd.get_program()))
}

/// Keeps the lab alive: the namespaces of `Network::create_netns` are deleted when it is dropped
#[must_use = "dropping the guard deletes the namespaces right away"]
pub struct NetnsGuard {
    /// Router last: deleting it also removes the bridges and the router ends of the veths
    namespaces: Vec<String>,
}

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        LAB_ALIVE.store(false, Ordering::Relaxed);
        for ns in &self.namespaces {
            delete_ns(ns);
        }
    }
}

/// A local subnet of the lab: a bridge in the router, with the gateway IP
struct LabSubnet<'a> {
    sub: &'a SubNetwork,
    bridge: String,
    gateway: Ipv4Addr,
}

/// Create a veth from the router to the namespace `ns`. `vr` stays in the router, `vh` is moved
/// into the namespace. Both are still down.
async fn plug(router: &Handle, ns: &str, vr: &str, vh: &str) -> Result<(), String> {
    router
        .link()
        .add(LinkVeth::new(vr, vh).build())
        .execute()
        .await
        .map_err(|e| format!("veth {vr}/{vh}: {e}"))?;
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
        .map_err(|e| format!("moving {vh} to {ns}: {e}"))
}

/// Give an address to `dev` and set it up. The thread must be in the namespace of `handle`.
async fn addr_up(handle: &Handle, dev: &str, ip: Ipv4Addr, prefix: u8) -> Result<u32, String> {
    let idx = ifindex(dev)?;
    handle
        .address()
        .add(idx, ip.into(), prefix)
        .execute()
        .await
        .map_err(|e| format!("address {ip}/{prefix} on {dev}: {e}"))?;
    handle
        .link()
        .set(LinkUnspec::new_with_index(idx).up().build())
        .execute()
        .await
        .map_err(|e| format!("{dev} up: {e}"))?;
    Ok(idx)
}

/// Add a namespace, like `ip netns add`
async fn add_ns(ns: &str) -> Result<(), String> {
    NetworkNamespace::add(ns)
        .await
        .map_err(|e| format!("namespace {ns}: {e}"))
}

impl Network {
    /// Hosts that get a namespace. Routers don't: the router of the lab plays them.
    /// If several hosts share an IP, only the first one gets a namespace.
    fn lab_hosts(&self) -> impl Iterator<Item = &Host> {
        let mut seen = HashSet::new();
        self.networks
            .iter()
            .flat_map(|n| &n.hosts)
            .filter(|h| h.host_type != HostType::Router && !h.interfaces.is_empty())
            .filter(move |h| {
                let ips = h.get_ip_addr();
                if let Some(ip) = ips.iter().find(|ip| seen.contains(*ip)) {
                    log_once::warn_once!(
                        "{ip} is used by several hosts, only the first one is in the lab"
                    );
                    return false;
                }
                seen.extend(ips);
                true
            })
    }

    /// Local subnets, each with its gateway: the IP of a router of the topology in that subnet,
    /// or else its first unused IP
    fn lab_subnets(&self) -> Result<Vec<LabSubnet<'_>>, String> {
        let used: HashSet<&Ipv4Addr> = self.all_ips.iter().collect();
        let routers: Vec<Ipv4Addr> = self
            .networks
            .iter()
            .flat_map(|n| &n.hosts)
            .filter(|h| h.host_type == HostType::Router)
            .flat_map(|h| h.get_ip_addr())
            .collect();
        self.networks
            .iter()
            .filter(|n| n.name != INTERNET_NETWORK_NAME)
            .enumerate()
            .map(|(i, sub)| {
                let network = u32::from(sub.subnet) & netmask(sub);
                let broadcast = network | !netmask(sub);
                let gateway = routers
                    .iter()
                    .copied()
                    .find(|ip| contains(sub, ip))
                    .or_else(|| {
                        (network + 1..broadcast)
                            .map(Ipv4Addr::from)
                            .find(|ip| !used.contains(ip))
                    })
                    .ok_or(format!(
                        "No free IP for the gateway of {network}/{}",
                        sub.mask
                    ))?;
                Ok(LabSubnet {
                    sub,
                    bridge: format!("br{i}"),
                    gateway,
                })
            })
            .collect()
    }

    /// Every namespace of the lab, router last
    fn namespaces(&self) -> Vec<String> {
        let mut namespaces: Vec<String> = self.lab_hosts().map(host_ns).collect();
        if self.has_internet_access {
            namespaces.push(INTERNET_NS.into());
        }
        namespaces.push(ROUTER_NS.into());
        namespaces
    }

    /// Create the router namespace, one bridge per subnet and one namespace per host.
    /// The namespaces are deleted when the returned guard is dropped.
    pub fn create_netns(&self) -> Result<NetnsGuard, String> {
        if !geteuid().is_root() {
            return Err("Creating network namespaces needs root privileges".into());
        }

        // 0. Remove leftovers of a previous run (maybe with another topology)
        delete_all_netns();

        // created first, so that an error below cleans up what was already made
        let guard = NetnsGuard {
            namespaces: self.namespaces(),
        };
        LAB_ALIVE.store(true, Ordering::Relaxed);
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

    /// Move the calling thread (only this one) into the namespace of the host that has `ip`
    pub fn enter_ns(&self, ip: &Ipv4Addr) -> Result<(), String> {
        let host = self
            .lab_hosts()
            .find(|h| h.get_ip_addr().contains(ip))
            .ok_or(format!("{ip} is not a host of the lab"))?;
        enter(&host_ns(host))
    }

    fn build_netns(&self) -> Result<(), String> {
        let subnets = self.lab_subnets()?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .map_err(|e| e.to_string())?;

        rt.block_on(async {
            // 1. Router: forwards everything, and is where the traffic is captured
            add_ns(ROUTER_NS).await?;
            enter(ROUTER_NS)?;
            let router = connect()?;
            std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").map_err(|e| e.to_string())?;

            // 2. Create one bridge for each subnet, with the gateway IP
            for s in &subnets {
                router
                    .link()
                    .add(LinkBridge::new(&s.bridge).build())
                    .execute()
                    .await
                    .map_err(|e| format!("bridge {}: {e}", s.bridge))?;
                router
                    .address()
                    .add(ifindex(&s.bridge)?, s.gateway.into(), s.sub.mask)
                    .execute()
                    .await
                    .map_err(|e| format!("gateway {} on {}: {e}", s.gateway, s.bridge))?;
            }

            for host in self.lab_hosts() {
                // 3. Create a namespace for each host, with one veth per interface
                let ns = host_ns(host);
                add_ns(&ns).await?;
                // what the host side needs: (vh, IP, prefix, gateway)
                let mut links = Vec::new();
                for ip in host.get_ip_addr() {
                    let (vr, vh) = veth_names(&ip);
                    plug(&router, &ns, &vr, &vh).await?;
                    let subnet = subnets
                        .iter()
                        .filter(|s| contains(s.sub, &ip))
                        .max_by_key(|s| s.sub.mask);
                    if let Some(s) = subnet {
                        // 4. In a subnet: plug the router end into its bridge
                        router
                            .link()
                            .set(
                                LinkUnspec::new_with_name(&vr)
                                    .controller(ifindex(&s.bridge)?)
                                    .up()
                                    .build(),
                            )
                            .execute()
                            .await
                            .map_err(|e| format!("{vr} into {}: {e}", s.bridge))?;
                        links.push((vh, ip, s.sub.mask, s.gateway));
                    } else {
                        // 4. Outside every subnet (public IPs, Internet hosts): point-to-point link
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
                            .map_err(|e| format!("route to {ip}: {e}"))?;
                        links.push((vh, ip, 32, LINK_GW));
                    }
                }

                // 5. Configure the host: IPs, interfaces up, default route through the first one
                enter(&ns)?;
                let h = connect()?;
                for (i, (vh, ip, prefix, gateway)) in links.into_iter().enumerate() {
                    let vh_idx = addr_up(&h, &vh, ip, prefix).await?;
                    if i == 0 {
                        // onlink: on a point-to-point link, the gateway is outside the host's /32
                        h.route()
                            .add(
                                RouteMessageBuilder::<Ipv4Addr>::new()
                                    .gateway(gateway)
                                    .output_interface(vh_idx)
                                    .onlink()
                                    .build(),
                            )
                            .execute()
                            .await
                            .map_err(|e| format!("default route of {ns}: {e}"))?;
                    }
                }
                enter(ROUTER_NS)?; // back, so that ifindex() finds the router interfaces
            }

            // 6. Anonymous Internet: one namespace that accepts every IP not routed elsewhere
            if self.has_internet_access {
                add_ns(INTERNET_NS).await?;
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
                // replies to the hosts of the lab go back to the router...
                for ip in self.lab_hosts().flat_map(|h| h.get_ip_addr()) {
                    inet.route()
                        .add(
                            RouteMessageBuilder::<Ipv4Addr>::new()
                                .destination_prefix(ip, 32)
                                .gateway(INET_ROUTER)
                                .build(),
                        )
                        .execute()
                        .await
                        .map_err(|e| format!("route to {ip}: {e}"))?;
                }
                // ...and every other destination is local (AnyIP). Not with throw routes in the
                // "local" table: without custom rules, the kernel treats a throw as unreachable.
                inet.route()
                    .add(
                        RouteMessageBuilder::<Ipv4Addr>::new()
                            .kind(RouteType::Local)
                            .scope(RouteScope::Host)
                            .output_interface(ifindex("lo")?)
                            .build(),
                    )
                    .execute()
                    .await
                    .map_err(|e| format!("local route: {e}"))?;

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

    /// Router ends of the veths: capturing on them sees each packet once, when it leaves its sender
    pub fn capture_ports(&self) -> Vec<String> {
        let mut ports: Vec<String> = self
            .lab_hosts()
            .flat_map(|h| h.get_ip_addr())
            .map(|ip| veth_names(&ip).0)
            .collect();
        if self.has_internet_access {
            ports.push(VR_INET.into());
        }
        ports
    }
}
