package org.batfish.netx;

import static org.batfish.netx.SnapshotFacts.JSON;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import org.batfish.common.NetworkSnapshot;
import org.batfish.common.plugin.TracerouteEngine;
import org.batfish.datamodel.Configuration;
import org.batfish.datamodel.Flow;
import org.batfish.datamodel.FlowDisposition;
import org.batfish.datamodel.Ip;
import org.batfish.datamodel.IpProtocol;
import org.batfish.datamodel.LineAction;
import org.batfish.datamodel.Prefix;
import org.batfish.datamodel.acl.AclTracer;
import org.batfish.datamodel.flow.FilterStep;
import org.batfish.datamodel.flow.RoutingStep;
import org.batfish.datamodel.flow.StepAction;
import org.batfish.datamodel.flow.Trace;
import org.batfish.datamodel.flow.TraceAndReverseFlow;
import org.batfish.datamodel.questions.BgpRoute;
import org.batfish.datamodel.routing_policy.Environment.Direction;
import org.batfish.datamodel.table.Row;
import org.batfish.datamodel.trace.TraceTree;
import org.batfish.main.Batfish;
import org.batfish.question.testroutepolicies.TestRoutePoliciesAnswerer;
import org.batfish.question.testroutepolicies.TestRoutePoliciesQuestion;

/** Uses the forwarding engine and policy evaluator on the same snapshot. */
final class SnapshotQueries {
  private static final int MAX_SAMPLED_FLOWS = 64;
  static final int MAX_PATHS_PER_FLOW = 256;
  private final TracerouteEngine traceroute;
  private final Batfish batfish;
  private final NetworkSnapshot snapshot;
  private final Map<String, Configuration> configs;

  SnapshotQueries(Batfish batfish, NetworkSnapshot snapshot, Map<String, Configuration> configs) {
    traceroute = batfish.getTracerouteEngine(snapshot);
    this.batfish = batfish;
    this.snapshot = snapshot;
    this.configs = configs;
  }

  record Result(String kind, String id, Object result, String error) {}

  record Paths(Flow flow, int totalPaths, List<Trace> traces, List<Denial> denials) {}

  record Denial(
      int pathIndex,
      String node,
      String iface,
      String direction,
      String filter,
      Flow packet,
      Integer ruleIndex,
      String rule,
      List<TraceTree> explanation) {}

  List<Result> run(JsonNode queries) {
    List<Result> results = new ArrayList<>();
    for (String kind : List.of("flows", "policyTests")) {
      for (JsonNode query : queries.path(kind)) {
        String id = query.required("id").asText();
        try {
          Object result =
              kind.equals("flows")
                  ? paths(JSON.convertValue(query.required("flow"), Flow.class).toBuilder().build())
                  : policyTest(query);
          results.add(new Result(kind, id, result, null));
        } catch (RuntimeException e) {
          results.add(new Result(kind, id, null, e.toString()));
        }
      }
    }
    if (queries.has("intentMembers")) {
      sampleIntentMembers(queries.get("intentMembers"), results);
    } else if (!queries.has("flows")) {
      sampleFlows(results);
    }
    return results;
  }

  record Endpoint(String node, String vrf, Ip ip) {}

  private List<Endpoint> endpoints() {
    List<Endpoint> endpoints = new ArrayList<>();
    new TreeMap<>(configs)
        .forEach(
            (node, config) ->
                config.getVrfs().keySet().stream()
                    .sorted()
                    .forEach(
                        vrf ->
                            config.getAllInterfaces(vrf).values().stream()
                                .filter(i -> i.getActive())
                                .flatMap(i -> i.getAllConcreteAddresses().stream())
                                .map(a -> a.getIp())
                                .min(Ip::compareTo)
                                .ifPresent(ip -> endpoints.add(new Endpoint(node, vrf, ip)))));
    return endpoints;
  }

  static Flow echo(Endpoint src, Ip dst) {
    return Flow.builder()
        .setIngressNode(src.node)
        .setIngressVrf(src.vrf)
        .setSrcIp(src.ip)
        .setDstIp(dst)
        .setIpProtocol(IpProtocol.ICMP)
        .setIcmpType(8)
        .setIcmpCode(0)
        .setPacketLength(64)
        .build();
  }

  static Ip destination(TreeSet<Ip> addresses, Ip source, Prefix prefix) {
    Ip dst = addresses.ceiling(prefix.getStartIp());
    if (source.equals(dst)) {
      Ip next = addresses.higher(dst);
      if (next != null && prefix.containsIp(next)) {
        dst = next;
      }
    }
    return dst != null && prefix.containsIp(dst) ? dst : prefix.getFirstHostIp();
  }

  /** Prefer a modeled destination within the member prefix, then its first usable address. */
  private void sampleIntentMembers(JsonNode members, List<Result> results) {
    List<Endpoint> sources = endpoints();
    TreeSet<Ip> addresses = new TreeSet<>();
    configs
        .values()
        .forEach(
            config ->
                config
                    .getActiveInterfaces()
                    .values()
                    .forEach(
                        iface ->
                            iface
                                .getAllConcreteAddresses()
                                .forEach(addr -> addresses.add(addr.getIp()))));
    int count = 0;
    for (JsonNode member : members) {
      String node = member.required("node").asText();
      Prefix prefix = Prefix.parse(member.required("prefix").asText());
      boolean found = false;
      for (Endpoint src : sources) {
        if (!src.node.equals(node)) {
          continue;
        }
        found = true;
        Ip dst = destination(addresses, src.ip, prefix);
        String id = "intent-" + ++count;
        try {
          results.add(new Result("flows", id, paths(echo(src, dst)), null));
        } catch (RuntimeException e) {
          results.add(new Result("flows", id, null, e.toString()));
        }
        if (count == MAX_SAMPLED_FLOWS) {
          return;
        }
      }
      if (!found) {
        results.add(
            new Result(
                "flows",
                "intent-" + ++count,
                null,
                "No active IPv4 source for " + node + " to " + prefix));
        if (count == MAX_SAMPLED_FLOWS) {
          return;
        }
      }
    }
  }

  /** Deterministic first 64 directed pairs of representative active VRF addresses. */
  private void sampleFlows(List<Result> results) {
    List<Endpoint> endpoints = endpoints();
    int count = 0;
    for (var src : endpoints) {
      for (var dst : endpoints) {
        if (src.node.equals(dst.node) || src.ip.equals(dst.ip)) {
          continue;
        }
        Flow flow = echo(src, dst.ip);
        results.add(new Result("flows", "sample-" + ++count, paths(flow), null));
        if (count == MAX_SAMPLED_FLOWS) {
          return;
        }
      }
    }
  }

  private Paths paths(Flow flow) {
    Configuration ingress = configs.get(flow.getIngressNode());
    if (ingress == null
        || (flow.getIngressInterface() == null
            ? !ingress.getVrfs().containsKey(flow.getIngressVrf())
            : !ingress.getActiveInterfaces().containsKey(flow.getIngressInterface()))) {
      throw new IllegalArgumentException("Unresolved or inactive flow start location");
    }
    var dag = traceroute.computeTraceDags(Set.of(flow), Set.of(), false).get(flow);
    var traces =
        dag.getAllTraces().limit(MAX_PATHS_PER_FLOW).map(TraceAndReverseFlow::getTrace).toList();
    List<Denial> denials = new ArrayList<>();
    for (int i = 0; i < traces.size(); i++) {
      for (var hop : traces.get(i).getHops()) {
        String node = hop.getNode().getName();
        String output = null;
        for (var step : hop.getSteps()) {
          if (step instanceof RoutingStep routing) {
            output = routing.getDetail().getOutputInterface();
          } else if (step instanceof FilterStep filter && step.getAction() == StepAction.DENIED) {
            denials.add(denial(i, node, output, filter));
          }
        }
      }
    }
    return new Paths(flow, dag.size(), traces, denials);
  }

  private Denial denial(int pathIndex, String node, String output, FilterStep filter) {
    var detail = filter.getDetail();
    var config = configs.get(node);
    var acl = config.getIpAccessLists().get(detail.getFilter());
    String input = detail.getInputInterface();
    Flow packet = detail.getFlow();
    // Replay the same packet at the same filter stage, including any preceding NAT.
    var match = acl.filter(packet, input, config.getIpAccessLists(), config.getIpSpaces());
    if (match.getAction() != LineAction.DENY) {
      throw new IllegalStateException("ACL replay disagrees with the forwarding trace");
    }
    Integer index = match.getMatchLine();
    boolean ingress = detail.getType().deniedDisposition() == FlowDisposition.DENIED_IN;
    return new Denial(
        pathIndex,
        node,
        ingress ? input : output,
        detail.getType().name(),
        acl.getName(),
        packet,
        index,
        index == null ? "implicit deny" : acl.getLines().get(index).getName(),
        AclTracer.trace(
            acl,
            packet,
            input,
            config.getIpAccessLists(),
            config.getIpSpaces(),
            config.getIpSpaceMetadata()));
  }

  private List<Row> policyTest(JsonNode query) {
    var route = JSON.convertValue(query.required("route"), BgpRoute.class);
    var question =
        new TestRoutePoliciesQuestion(
            Direction.valueOf(query.required("direction").textValue()),
            List.of(route),
            query.required("nodes").textValue(),
            query.required("policies").textValue(),
            null);
    var rows = new TestRoutePoliciesAnswerer(question, batfish).answer(snapshot).getRowsList();
    if (rows.isEmpty()) {
      throw new IllegalArgumentException("No matching policy on the selected nodes");
    }
    return rows;
  }
}
