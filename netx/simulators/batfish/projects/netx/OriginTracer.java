package org.batfish.netx;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.batfish.datamodel.Bgpv4Route;
import org.batfish.datamodel.OriginMechanism;
import org.batfish.datamodel.Prefix;
import org.batfish.datamodel.PrefixSpace;
import org.batfish.datamodel.ReceivedFromSelf;
import org.batfish.datamodel.bgp.BgpTopology;
import org.batfish.datamodel.bgp.BgpTopology.EdgeId;
import org.batfish.dataplane.ibdp.PrefixTracer;

/** Retain locally originated IPv4 routes actually advertised to each established peer. */
final class OriginTracer extends PrefixTracer {
  record Export(
      String node,
      String vrf,
      Prefix prefix,
      String peer,
      String peerVrf,
      String peerIp,
      OriginMechanism mechanism,
      String sourceProtocol) {}

  private final PrefixSpace focus;
  private final Map<EdgeId, Set<Bgpv4Route>> active = new ConcurrentHashMap<>();

  OriginTracer(PrefixSpace focus) {
    super(focus);
    this.focus = focus;
  }

  @Override
  protected void sessionOpened(EdgeId edge) {
    active.remove(edge);
  }

  @Override
  protected void exportedAdvertisement(EdgeId edge, Bgpv4Route route, boolean withdrawn) {
    if (!route.getReceivedFrom().equals(ReceivedFromSelf.instance())
        || route.getOriginMechanism() == OriginMechanism.LEARNED
        || !focus.containsPrefix(route.getNetwork())) {
      return;
    }
    Set<Bgpv4Route> routes = active.computeIfAbsent(edge, ignored -> ConcurrentHashMap.newKeySet());
    if (withdrawn) {
      routes.remove(route);
    } else {
      routes.add(route);
    }
  }

  List<Export> exports(BgpTopology topology) {
    return active.entrySet().stream()
        .filter(
            entry ->
                topology.getGraph().hasEdgeConnecting(entry.getKey().tail(), entry.getKey().head()))
        .flatMap(
            entry -> {
              EdgeId edge = entry.getKey();
              String peerIp =
                  topology
                      .getGraph()
                      .edgeValue(edge.tail(), edge.head())
                      .orElseThrow()
                      .getRemoteIp()
                      .toString();
              return entry.getValue().stream()
                  .map(
                      route ->
                          new Export(
                              edge.tail().getHostname(),
                              edge.tail().getVrfName(),
                              route.getNetwork(),
                              edge.head().getHostname(),
                              edge.head().getVrfName(),
                              peerIp,
                              route.getOriginMechanism(),
                              route.getSrcProtocol().protocolName()));
            })
        .distinct()
        .toList();
  }
}
