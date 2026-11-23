package org.batfish.netx;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.batfish.datamodel.Configuration;
import org.batfish.datamodel.Prefix;
import org.batfish.datamodel.PrefixSpace;
import org.batfish.datamodel.bgp.BgpTopology;
import org.batfish.datamodel.routing_policy.Environment.Direction;
import org.batfish.dataplane.ibdp.IncrementalDataPlanePlugin;
import org.batfish.dataplane.ibdp.Node;
import org.batfish.dataplane.ibdp.PrefixTracer;

/** One plugin per NetX run. Retains the neighbor and policy discarded by the prefix summary. */
final class TracingDataPlanePlugin extends IncrementalDataPlanePlugin {
  record Location(String node, String vrf) {}

  record Event(
      String node,
      String vrf,
      Prefix prefix,
      String direction,
      String action,
      String peer,
      String peerVrf,
      String peerIp,
      String policy) {}

  private final PrefixSpace prefixes;
  private final Map<Location, OriginTracer> tracers = new ConcurrentHashMap<>();

  TracingDataPlanePlugin(PrefixSpace prefixes) {
    this.prefixes = prefixes;
  }

  @Override
  public String getName() {
    return "netx-tracing";
  }

  @Override
  protected Node createNode(Configuration config) {
    return new Node(
        config,
        vrf -> {
          OriginTracer tracer = new OriginTracer(prefixes);
          tracers.put(new Location(config.getHostname(), vrf), tracer);
          return tracer;
        },
        true);
  }

  List<OriginTracer.Export> originExports(BgpTopology topology) {
    return tracers.values().stream().flatMap(t -> t.exports(topology).stream()).toList();
  }

  List<Event> events() {
    List<Event> events = new ArrayList<>();
    tracers.forEach(
        (location, tracer) -> {
          addEvents(events, location, tracer.getFiltered(Direction.IN), "import", "rejected");
          addEvents(events, location, tracer.getFiltered(Direction.OUT), "export", "rejected");
          addEvents(events, location, tracer.getSent(), "export", "sent");
        });
    return events;
  }

  private static void addEvents(
      List<Event> events,
      Location local,
      Map<Prefix, Set<PrefixTracer.Neighbor>> records,
      String direction,
      String action) {
    records.forEach(
        (prefix, peers) ->
            peers.forEach(
                peer ->
                    events.add(
                        new Event(
                            local.node(),
                            local.vrf(),
                            prefix,
                            direction,
                            action,
                            peer.getHostname(),
                            peer.getVrfname(),
                            peer.getIp().toString(),
                            peer.getRoutingPolicy()))));
  }
}
