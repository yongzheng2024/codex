package org.batfish.netx;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.batfish.common.NetworkSnapshot;
import org.batfish.datamodel.Configuration;
import org.batfish.datamodel.Fib;
import org.batfish.datamodel.FibForward;
import org.batfish.datamodel.FibNullRoute;
import org.batfish.datamodel.Flow;
import org.batfish.datamodel.FlowDiff;
import org.batfish.datamodel.FlowDisposition;
import org.batfish.datamodel.Ip;
import org.batfish.datamodel.Prefix;
import org.batfish.datamodel.Topology;
import org.batfish.datamodel.collections.NodeInterfacePair;
import org.batfish.datamodel.flow.Trace;
import org.batfish.datamodel.flow.TraceAndReverseFlow;
import org.batfish.datamodel.flow.TransformationStep;
import org.batfish.main.Batfish;

/** Compact observations for supplied IPv4 intents from the device-role data plane. */
final class IntentObservations {
  private static final int BATCH_SIZE = 128;

  static List<Map<String, Object>> collect(
      Batfish batfish,
      NetworkSnapshot snapshot,
      Map<String, Configuration> configs,
      JsonNode members) {
    var outputs = new ArrayList<Map<String, Object>>();
    var addresses = new TreeSet<Ip>();
    var sources = new LinkedHashMap<String, Ip>();
    for (var config : configs.values()) {
      if (!config.getVrfs().containsKey("default")) continue;
      var local = new TreeSet<Ip>();
      for (var iface : config.getAllInterfaces("default").values()) {
        if (iface.getActive()) iface.getAllConcreteAddresses().forEach(a -> local.add(a.getIp()));
      }
      addresses.addAll(local);
      if (!local.isEmpty()) sources.put(config.getHostname(), local.first());
    }
    var plane = batfish.loadDataPlane(snapshot);
    var topology = batfish.getTopologyProvider().getLayer3Topology(snapshot);
    var engine = batfish.getTracerouteEngine(snapshot);
    var requests = new LinkedHashMap<Flow, List<Map<String, Object>>>();
    for (JsonNode member : members) {
      String node = member.required("node").textValue();
      var prefix = Prefix.parse(member.required("prefix").textValue());
      var row = new LinkedHashMap<String, Object>();
      outputs.add(row);
      row.put("node", node);
      row.put("prefix", prefix.toString());
      var src = sources.get(node);
      if (src == null) {
        row.put("error", "No active IPv4 source in the default VRF");
        continue;
      }
      var dst = SnapshotQueries.destination(addresses, src, prefix);
      row.put("sourceIp", src.toString());
      row.put("destination", dst.toString());
      var fib = plane.getFibs().getOrDefault(node, Map.of()).get("default");
      row.put("nextHopNodes", neighbors(configs, topology, fib, node, dst));
      var flow = SnapshotQueries.echo(new SnapshotQueries.Endpoint(node, "default", src), dst);
      requests.computeIfAbsent(flow, unused -> new ArrayList<>()).add(row);
    }
    var flows = new ArrayList<>(requests.keySet());
    for (int start = 0; start < flows.size(); start += BATCH_SIZE) {
      var batch = Set.copyOf(flows.subList(start, Math.min(start + BATCH_SIZE, flows.size())));
      var dags = engine.computeTraceDags(batch, Set.of(), false);
      for (var flow : batch) {
        var dag = dags.get(flow);
        var traces =
            dag.getAllTraces()
                .limit(SnapshotQueries.MAX_PATHS_PER_FLOW)
                .map(TraceAndReverseFlow::getTrace)
                .toList();
        var observations = summarize(traces, dag.size(), flow.getDstIp().toString());
        requests.get(flow).forEach(row -> row.putAll(observations));
      }
    }
    return outputs;
  }

  /** Distinct adjacent routers for resolved forwarding actions in the longest-prefix FIB lookup. */
  private static Set<String> neighbors(
      Map<String, Configuration> configs, Topology topology, Fib fib, String node, Ip destination) {
    if (fib == null) return null;
    var nodes = new TreeSet<String>();
    for (var entry : fib.get(destination)) {
      if (entry.getAction() instanceof FibNullRoute) continue;
      if (!(entry.getAction() instanceof FibForward forward)) return null;
      var iface = forward.getInterfaceName();
      var local = configs.get(node).getAllInterfaces().get(iface);
      if (local != null
          && local.getAllConcreteAddresses().stream().anyMatch(a -> a.getIp().equals(destination)))
        continue;
      var target = forward.getArpIp().orElse(destination);
      var owners = new TreeSet<String>();
      for (var peer : topology.getNeighbors(NodeInterfacePair.of(node, iface))) {
        var port = configs.get(peer.getHostname()).getAllInterfaces().get(peer.getInterface());
        if (port != null
            && port.getAllConcreteAddresses().stream().anyMatch(a -> a.getIp().equals(target)))
          owners.add(peer.getHostname());
      }
      if (owners.size() != 1) return null;
      nodes.addAll(owners);
    }
    return nodes;
  }

  private static Map<String, Object> summarize(List<Trace> traces, int total, String destination) {
    var outcomes = new TreeSet<String>();
    var common = new TreeSet<String>();
    boolean received = false;
    boolean complete = !traces.isEmpty() && traces.size() == total;
    for (var trace : traces) {
      var end = trace.getDisposition();
      outcomes.add(end.toString());
      if (end == FlowDisposition.INSUFFICIENT_INFO
          || end == FlowDisposition.EXITS_NETWORK
          || end == FlowDisposition.DELIVERED_TO_SUBNET) complete = false;
      if (end != FlowDisposition.ACCEPTED) continue;
      String acceptedIp =
          trace.getHops().stream()
              .flatMap(h -> h.getSteps().stream())
              .filter(TransformationStep.class::isInstance)
              .map(TransformationStep.class::cast)
              .flatMap(t -> t.getDetail().getFlowDiffs().stream())
              .filter(d -> "dstIp".equals(d.getFieldName()))
              .map(FlowDiff::getNewValue)
              .reduce((previous, current) -> current)
              .orElse(destination);
      if (!destination.equals(acceptedIp)) continue;
      var path = trace.getHops();
      var transit = new TreeSet<String>();
      for (int i = 1; i < path.size(); i++) {
        transit.add(path.get(i).getNode().getName());
      }
      transit.remove(path.get(0).getNode().getName());
      if (received) common.retainAll(transit);
      else common.addAll(transit);
      received = true;
    }
    var result = new LinkedHashMap<String, Object>();
    result.put("received", received ? Boolean.TRUE : (complete ? Boolean.FALSE : null));
    result.put("waypoints", complete ? common : null);
    result.put("dispositions", outcomes);
    result.put("totalPaths", total);
    result.put("examinedPaths", traces.size());
    return result;
  }

  private IntentObservations() {}
}
