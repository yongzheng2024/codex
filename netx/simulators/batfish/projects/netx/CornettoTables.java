package org.batfish.netx;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.stream.LongStream;
import org.batfish.common.Answerer;
import org.batfish.common.NetworkSnapshot;
import org.batfish.datamodel.AbstractRoute;
import org.batfish.datamodel.Configuration;
import org.batfish.datamodel.FinalMainRib;
import org.batfish.datamodel.Flow;
import org.batfish.datamodel.Interface;
import org.batfish.datamodel.Ip;
import org.batfish.datamodel.IpAccessList;
import org.batfish.datamodel.IpSpace;
import org.batfish.datamodel.LineAction;
import org.batfish.datamodel.Prefix;
import org.batfish.datamodel.Route;
import org.batfish.datamodel.RoutingProtocol;
import org.batfish.datamodel.Topology;
import org.batfish.datamodel.VrfForwardingBehavior;
import org.batfish.datamodel.collections.NodeInterfacePair;
import org.batfish.datamodel.questions.Question;
import org.batfish.datamodel.route.nh.NextHopDiscard;
import org.batfish.datamodel.route.nh.NextHopVrf;
import org.batfish.datamodel.table.Row;
import org.batfish.datamodel.table.TableAnswerElement;
import org.batfish.main.Batfish;
import org.batfish.question.edges.EdgesQuestion;
import org.batfish.question.ipowners.IpOwnersQuestion;

/** The graph-relevant columns of Cornetto's forwarding-analysis-0.1 question on the NetX plane. */
final class CornettoTables {
  // NOTE: Cornetto's forwarding-analysis-0.1 question orders both output and recursive
  // next-hop candidates this way. Graph grouping retains the first equivalent prefix.
  private static final Comparator<AbstractRoute> ROUTES =
      Comparator.comparing(AbstractRoute::getNetwork)
          .thenComparing(CornettoTables::iface, Comparator.nullsFirst(Comparator.naturalOrder()))
          .thenComparing(
              AbstractRoute::getNextHopIp, Comparator.nullsFirst(Comparator.naturalOrder()))
          .thenComparing(r -> r.getProtocol().protocolName());

  static Map<String, ?> collect(Batfish batfish, NetworkSnapshot snapshot) {
    var plane = batfish.loadDataPlane(snapshot);
    var configs = batfish.loadConfigurations(snapshot);
    var topology = batfish.getTopologyProvider().getLayer3Topology(snapshot);
    var behavior = plane.getForwardingAnalysis().getVrfForwardingBehavior();
    var rows = new ArrayList<Row>();
    for (var config : configs.values()) {
      var node = config.getHostname();
      for (var entry : new TreeMap<>(plane.getRibs().row(node)).entrySet()) {
        var vrf = entry.getKey();
        var rib = entry.getValue();
        var forwarding = behavior.getOrDefault(node, Map.of()).get(vrf);
        for (var route : rib.getRoutes().stream().sorted(ROUTES).toList()) {
          String iface = resolveInterface(route, rib);
          var samples = destinations(route.getNetwork());
          var action = filterAction(config, iface, samples, configs, topology);
          if (action == null) {
            action = routeAction(route, iface, samples, forwarding, config.getIpSpaces());
          }
          rows.add(
              Row.builder()
                  .put("Node", node)
                  .put("VRF", vrf)
                  .put("Prefix", route.getNetwork())
                  .put("Action", action)
                  .put("Next_Hop_Interface", iface)
                  .put("Next_Hop_IP", route.getNextHopIp())
                  .build());
        }
      }
    }
    return Map.of(
        "forwarding",
        rows,
        "ipOwners",
        answer(new IpOwnersQuestion(null, false), batfish, snapshot),
        "layer1",
        answer(
            new EdgesQuestion(null, null, EdgesQuestion.EdgeType.LAYER1, false),
            batfish,
            snapshot));
  }

  private static List<Row> answer(Question question, Batfish batfish, NetworkSnapshot snapshot) {
    return ((TableAnswerElement) Answerer.create(question, batfish).answer(snapshot)).getRowsList();
  }

  private static String iface(AbstractRoute route) {
    var name = route.getNextHopInterface();
    return Route.UNSET_NEXT_HOP_INTERFACE.equals(name) ? null : name;
  }

  private static String resolveInterface(AbstractRoute route, FinalMainRib rib) {
    // NOTE: Cornetto resolves the interface through at most ten RIB lookups and keeps the
    // original next-hop IP in the row for the extractor's IP-owner lookup.
    String iface = iface(route);
    Ip address = route.getNextHopIp();
    var seen = new HashSet<Ip>();
    while (iface == null && address != null && seen.size() < 10 && seen.add(address)) {
      var matches = rib.longestPrefixMatch(address).stream().sorted(ROUTES).toList();
      iface =
          matches.stream()
              .map(CornettoTables::iface)
              .filter(Objects::nonNull)
              .findFirst()
              .orElse(null);
      address =
          matches.stream()
              .map(AbstractRoute::getNextHopIp)
              .filter(Objects::nonNull)
              .findFirst()
              .orElse(null);
    }
    return iface;
  }

  // NOTE: Cornetto samples the endpoints, their immediate neighbors and the midpoint
  // for both forwarding dispositions and ACL decisions, including /31 and /32 prefixes.
  private static List<Ip> destinations(Prefix prefix) {
    long lo = prefix.getStartIp().asLong(), hi = prefix.getEndIp().asLong();
    return LongStream.of(lo, Math.min(hi, lo + 1), Math.max(lo, hi - 1), lo + (hi - lo + 1) / 2, hi)
        .distinct()
        .mapToObj(Ip::create)
        .toList();
  }

  private static boolean contains(IpSpace space, List<Ip> samples, Map<String, IpSpace> named) {
    return space != null && samples.stream().anyMatch(ip -> space.containsIp(ip, named));
  }

  private static String routeAction(
      AbstractRoute route,
      String iface,
      List<Ip> samples,
      VrfForwardingBehavior vrf,
      Map<String, IpSpace> named) {
    if (route.getNextHop() instanceof NextHopVrf) {
      return "delegated_to_vrf";
    }
    if (route.getNextHop() instanceof NextHopDiscard) {
      return "null_routed";
    }
    String name = iface == null ? "" : iface.toLowerCase(Locale.ROOT);
    // NOTE: Cornetto connects an accepted route to the prefix vertex. An ordinary connected
    // subnet ends at delivered_to_subnet even when a trace to an interface IP is accepted.
    if (name.startsWith("loopback")) {
      return "accepted";
    }
    if (name.startsWith("null")) {
      return "null_routed";
    }
    if (route.getProtocol() == RoutingProtocol.LOCAL) {
      return "accepted";
    }
    if (route.getProtocol() == RoutingProtocol.CONNECTED) {
      return "delivered_to_subnet";
    }
    if (vrf != null) {
      var output = iface == null ? null : vrf.getInterfaceForwardingBehavior().get(iface);
      if (output != null) {
        if (contains(output.getDeliveredToSubnet(), samples, named)) {
          return "delivered_to_subnet";
        }
        if (contains(output.getAcceptedIps(), samples, named)) {
          return "accepted";
        }
        if (contains(output.getExitsNetwork(), samples, named)) {
          return "forwarded";
        }
        if (contains(output.getInsufficientInfo(), samples, named)) {
          return "insufficient_info";
        }
        if (contains(output.getNeighborUnreachable(), samples, named)) {
          return "neighbor_unreachable";
        }
      }
      if (contains(vrf.getNullRoutedIps(), samples, named)) {
        return "null_routed";
      }
      if (!contains(vrf.getRoutableIps(), samples, named)) {
        return "no_route";
      }
    }
    return iface == null ? "unknown" : "forwarded";
  }

  private static boolean deniesAll(Interface port, IpAccessList acl, Ip source, List<Ip> samples) {
    if (acl == null) {
      return false;
    }
    var config = port.getOwner();
    for (var dst : samples) {
      var flow =
          Flow.builder()
              .setIngressNode(config.getHostname())
              .setIngressInterface(port.getName())
              .setSrcIp(source)
              .setDstIp(dst)
              .build();
      if (acl.filter(flow, port.getName(), config.getIpAccessLists(), config.getIpSpaces())
              .getAction()
          == LineAction.PERMIT) {
        return false;
      }
    }
    return true;
  }

  private static String filterAction(
      Configuration config,
      String iface,
      List<Ip> samples,
      Map<String, Configuration> configs,
      Topology topology) {
    // NOTE: Cornetto checks the outgoing filter first. An incoming block requires every
    // neighboring ingress to deny every sampled destination on this egress.
    if (iface == null) {
      return null;
    }
    var output = config.getAllInterfaces().get(iface);
    if (output == null) {
      return null;
    }
    var source =
        output.getConcreteAddress() == null ? Ip.ZERO : output.getConcreteAddress().getIp();
    if (deniesAll(output, output.getOutgoingFilter(), source, samples)) {
      return "forwarded_blocked_outgoing_filter";
    }
    var peers = topology.getNeighbors(NodeInterfacePair.of(config.getHostname(), iface));
    for (var peer : peers) {
      var remote = configs.get(peer.getHostname());
      var input = remote == null ? null : remote.getAllInterfaces().get(peer.getInterface());
      if (input == null || !deniesAll(input, input.getIncomingFilter(), source, samples)) {
        return null;
      }
    }
    return peers.isEmpty() ? null : "forwarded_blocked_incoming_filter";
  }

  private CornettoTables() {}
}
