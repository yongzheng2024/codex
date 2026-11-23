package org.batfish.netx;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.batfish.datamodel.AbstractRoute;
import org.batfish.datamodel.BgpPeerConfigId.BgpPeerConfigType;
import org.batfish.datamodel.ConcreteInterfaceAddress;
import org.batfish.datamodel.Configuration;
import org.batfish.datamodel.DataPlane;
import org.batfish.datamodel.Ip;
import org.batfish.datamodel.PrefixSpace;
import org.batfish.datamodel.VrfLeakConfig;
import org.batfish.datamodel.bgp.BgpTopology;
import org.batfish.datamodel.questions.BgpRouteStatus;
import org.batfish.datamodel.route.nh.NextHop;

/** Joins candidate identity across the BGP RIB, main RIB and resolved FIB. */
final class RoutingFacts {
  record Route(
      String node,
      String vrf,
      String protocol,
      NextHop nextHop,
      AbstractRoute attributes,
      BgpRouteStatus bgpStatus,
      boolean inMainRib,
      boolean inFib) {}

  record Domain(
      String node,
      String vrf,
      List<String> interfaces,
      VrfLeakConfig configuredLeaks,
      Map<String, List<ConcreteInterfaceAddress>> activeAddresses,
      boolean runsOspf,
      String isisSystemId) {}

  record Session(String node, String vrf, Ip localIp, String peer, String peerVrf, Ip peerIp) {}

  /** Numbered sessions identify the receiver-side received-from address for a sent prefix. */
  static List<Session> numberedSessions(BgpTopology topology) {
    List<Session> sessions = new ArrayList<>();
    var graph = topology.getGraph();
    for (var edge : graph.edges()) {
      var local = edge.source();
      var remote = edge.target();
      if (local.getType() == BgpPeerConfigType.UNNUMBERED
          || remote.getType() == BgpPeerConfigType.UNNUMBERED) {
        continue;
      }
      var properties = graph.edgeValue(local, remote).orElseThrow();
      sessions.add(
          new Session(
              local.getHostname(),
              local.getVrfName(),
              properties.getLocalIp(),
              remote.getHostname(),
              remote.getVrfName(),
              properties.getRemoteIp()));
    }
    return sessions;
  }

  static List<Route> routes(DataPlane plane, PrefixSpace focus) {
    List<Route> rows = new ArrayList<>();
    var best = plane.getBgpRoutes();
    var backup = plane.getBgpBackupRoutes();
    for (var cell : plane.getRibs().cellSet()) {
      String node = cell.getRowKey();
      String vrf = cell.getColumnKey();
      Set<AbstractRoute> fib = new HashSet<>();
      plane.getFibs().get(node).get(vrf).allEntries().forEach(e -> fib.add(e.getTopLevelRoute()));
      var main = cell.getValue().getRoutes();
      Map<AbstractRoute, BgpRouteStatus> candidates = new HashMap<>();
      backup
          .row(node)
          .getOrDefault(vrf, Set.of())
          .forEach(r -> candidates.put(r, BgpRouteStatus.BACKUP));
      best.row(node)
          .getOrDefault(vrf, Set.of())
          .forEach(r -> candidates.put(r, BgpRouteStatus.BEST));
      Set<AbstractRoute> routes = new HashSet<>(main);
      routes.addAll(candidates.keySet());
      for (var route : routes) {
        if (focus.containsPrefix(route.getNetwork())) {
          rows.add(
              new Route(
                  node,
                  vrf,
                  route.getProtocol().protocolName(),
                  route.getNextHop(),
                  route,
                  candidates.get(route),
                  main.contains(route),
                  fib.contains(route)));
        }
      }
    }
    return rows;
  }

  /** Converted peer policies retain the vendor policy names used by synthetic wrappers. */
  static Map<String, Map<String, Set<String>>> policySources(Map<String, Configuration> configs) {
    Map<String, Map<String, Set<String>>> result = new TreeMap<>();
    configs.forEach(
        (node, config) -> {
          Map<String, Set<String>> policies = new TreeMap<>();
          for (var vrf : config.getVrfs().values()) {
            if (vrf.getBgpProcess() == null) {
              continue;
            }
            for (var peer : vrf.getBgpProcess().getAllPeerConfigs()) {
              for (var family : peer.getAllAddressFamilies()) {
                if (family.getImportPolicy() != null) {
                  policies.put(family.getImportPolicy(), family.getImportPolicySources());
                }
                if (family.getExportPolicy() != null) {
                  policies.put(family.getExportPolicy(), family.getExportPolicySources());
                }
              }
            }
          }
          result.put(node, policies);
        });
    return result;
  }

  static List<Domain> domains(Map<String, Configuration> configs) {
    List<Domain> rows = new ArrayList<>();
    configs.forEach(
        (node, config) ->
            config
                .getVrfs()
                .forEach(
                    (name, vrf) -> {
                      var interfaces = config.getAllInterfaces(name);
                      Map<String, List<ConcreteInterfaceAddress>> addresses = new TreeMap<>();
                      interfaces.forEach(
                          (iface, value) -> {
                            if (value.getActive() && !value.getAllConcreteAddresses().isEmpty()) {
                              addresses.put(
                                  iface,
                                  value.getAllConcreteAddresses().stream().sorted().toList());
                            }
                          });
                      rows.add(
                          new Domain(
                              node,
                              name,
                              interfaces.keySet().stream().sorted().toList(),
                              vrf.getVrfLeakConfig(),
                              addresses,
                              !vrf.getOspfProcesses().isEmpty(),
                              vrf.getIsisProcess() == null
                                  ? null
                                  : vrf.getIsisProcess().getNetAddress().getSystemIdString()));
                    }));
    return rows;
  }
}
