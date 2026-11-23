package org.batfish.netx;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import org.batfish.common.BatfishLogger;
import org.batfish.common.NetworkSnapshot;
import org.batfish.common.util.BatfishObjectMapper;
import org.batfish.config.Settings;
import org.batfish.datamodel.Prefix;
import org.batfish.datamodel.PrefixRange;
import org.batfish.datamodel.PrefixSpace;
import org.batfish.identifiers.NetworkId;
import org.batfish.identifiers.SnapshotId;
import org.batfish.main.Batfish;
import org.batfish.storage.FileBasedStorage;
import org.batfish.version.BatfishVersion;

/** Runs a snapshot in a private storage directory owned by the caller. */
public final class SnapshotFacts {
  static final ObjectMapper JSON = BatfishObjectMapper.mapper();

  public static void main(String[] args) throws IOException {
    if (args.length != 4) {
      throw new IllegalArgumentException(
          "Expected snapshot directory, queries JSON, new work directory, output JSON");
    }
    Path input = Path.of(args[0]);
    JsonNode queries = JSON.readTree(Path.of(args[1]).toFile());
    Path storageRoot = Files.createDirectory(Path.of(args[2]));
    Settings settings = new Settings(new String[0]);
    settings.setLogger(new BatfishLogger("warn", false));
    settings.setStorageBase(storageRoot);
    settings.setContainer("netx");
    settings.setTestrig("current");
    settings.setSnapshotName("current");
    PrefixSpace focus = new PrefixSpace();
    if (queries.has("prefixes")) {
      queries.get("prefixes").forEach(p -> focus.addPrefix(Prefix.parse(p.textValue())));
    } else {
      focus.addPrefixRange(PrefixRange.ALL);
    }
    TracingDataPlanePlugin plugin = new TracingDataPlanePlugin(focus);
    settings.setDataplaneEngineName(plugin.getName());
    FileBasedStorage storage = new FileBasedStorage(storageRoot, settings.getLogger());
    NetworkSnapshot snapshot =
        new NetworkSnapshot(new NetworkId("netx"), new SnapshotId("current"));
    try (var paths = Files.walk(input)) {
      for (Path file : paths.filter(Files::isRegularFile).toList()) {
        try (var stream = Files.newInputStream(file)) {
          storage.storeSnapshotInputObject(stream, input.relativize(file).toString(), snapshot);
        }
      }
    }
    Batfish batfish =
        new Batfish(
            settings,
            Caffeine.newBuilder().build(),
            Caffeine.newBuilder().build(),
            Collections.synchronizedMap(new HashMap<>()),
            Caffeine.newBuilder().build(),
            storage,
            null);
    plugin.initialize(batfish);
    var configs = batfish.loadConfigurations(snapshot);
    if (configs.isEmpty()) {
      throw new IllegalArgumentException("No device configurations could be loaded");
    }
    batfish.computeDataPlane(snapshot);
    var parse = batfish.loadParseVendorConfigurationAnswerElement(snapshot);
    var convert = batfish.loadConvertConfigurationAnswerElementOrReparse(snapshot);
    Map<String, Object> facts = new LinkedHashMap<>();
    facts.put("batfishVersion", BatfishVersion.getVersionStatic());
    facts.put("bgpMultipathExport", "speclens_compatible");
    facts.put("parseStatus", parse.getParseStatus());
    facts.put("parseWarnings", parse.getWarnings());
    facts.put("conversionWarnings", convert.getWarnings());
    facts.put("conversionStatus", convert.getConvertStatus());
    facts.put("definitions", convert.getDefinedStructures());
    facts.put("policySources", RoutingFacts.policySources(configs));
    facts.put("files", parse.getFileMap().asMap());
    facts.put("layer3Edges", batfish.getTopologyProvider().getLayer3Topology(snapshot).getEdges());
    facts.put("domains", RoutingFacts.domains(configs));
    var bgpTopology = batfish.getTopologyProvider().getBgpTopology(snapshot);
    facts.put("bgpSessions", RoutingFacts.numberedSessions(bgpTopology));
    facts.put("routes", RoutingFacts.routes(batfish.loadDataPlane(snapshot), focus));
    facts.put("events", plugin.events());
    facts.put("originExports", plugin.originExports(bgpTopology));
    SnapshotQueries analysis = new SnapshotQueries(batfish, snapshot, configs);
    facts.put("queries", analysis.run(queries));
    BatfishObjectMapper.verboseMapper().writeValue(Path.of(args[3]).toFile(), facts);
  }
}
