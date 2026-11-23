import com.google.common.cache.CacheBuilder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.batfish.common.Answerer;
import org.batfish.common.BatfishLogger;
import org.batfish.common.NetworkSnapshot;
import org.batfish.common.util.BatfishObjectMapper;
import org.batfish.config.Settings;
import org.batfish.datamodel.questions.Question;
import org.batfish.datamodel.table.TableAnswerElement;
import org.batfish.dataplane.ibdp.IncrementalDataPlanePlugin;
import org.batfish.identifiers.NetworkId;
import org.batfish.identifiers.SnapshotId;
import org.batfish.main.Batfish;
import org.batfish.question.edges.EdgesQuestion;
import org.batfish.question.forwardingbehaviortable.ForwardingBehaviorTableQuestion;
import org.batfish.question.ipowners.IpOwnersQuestion;
import org.batfish.storage.FileBasedStorage;

/** Independent control using the scorer's engine, standard data plane and question bundle. */
public final class CornettoReference {
  private static TableAnswerElement table(
      Question question, Batfish batfish, NetworkSnapshot snapshot) {
    return (TableAnswerElement) Answerer.create(question, batfish).answer(snapshot);
  }

  public static void main(String[] args) throws Exception {
    Path input = Path.of(args[0]);
    Path work = Files.createDirectory(Path.of(args[1]));
    var settings = new Settings(new String[0]);
    settings.setLogger(new BatfishLogger("warn", false));
    settings.setStorageBase(work);
    settings.setContainer("netx");
    settings.setTestrig("current");
    settings.setSnapshotName("current");
    var storage = new FileBasedStorage(work, settings.getLogger());
    var snapshot = new NetworkSnapshot(new NetworkId("netx"), new SnapshotId("current"));
    try (var paths = Files.walk(input)) {
      for (Path file : paths.filter(Files::isRegularFile).toList()) {
        try (var stream = Files.newInputStream(file)) {
          storage.storeSnapshotInputObject(stream, input.relativize(file).toString(), snapshot);
        }
      }
    }
    var batfish =
        new Batfish(
            settings,
            CacheBuilder.newBuilder().build(),
            CacheBuilder.newBuilder().build(),
            Collections.synchronizedMap(new HashMap<>()),
            CacheBuilder.newBuilder().build(),
            storage,
            null);
    new IncrementalDataPlanePlugin().initialize(batfish);
    batfish.computeDataPlane(snapshot);
    BatfishObjectMapper.verboseMapper()
        .writeValue(
            Path.of(args[2]).toFile(),
            Map.of(
                "forwarding", table(new ForwardingBehaviorTableQuestion(), batfish, snapshot),
                "layer1",
                    table(
                        new EdgesQuestion(null, null, EdgesQuestion.EdgeType.LAYER1, false),
                        batfish,
                        snapshot),
                "ipOwners", table(new IpOwnersQuestion(null, false), batfish, snapshot)));
  }
}
