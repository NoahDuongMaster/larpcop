//! gRPC service methods: the client's message arrives as a parameter.

use super::tests_calls::found;
use super::tests_support::guarded_config;
use super::*;
use crate::config::TaintConfig;

fn reported(lang: &str, rel: &str, src: &str) -> Vec<usize> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(rel), src).unwrap();
    let cfg = TaintConfig {
        handler_classes: Some(r"ImplBase\b|Servicer\b".into()),
        input_types: Some(r"^\*\w+\.\w+Request$".into()),
        ..guarded_config(
            lang,
            &["$R.getParameter($K)"],
            &["db.query($X)", "db.Query($X)"],
            &[],
            &[],
        )
    };
    let rule = TaintRule::new(&cfg, typed::Typed::default(), dir.path().to_path_buf()).unwrap();
    found(&rule, dir.path(), rel)
        .iter()
        .map(|(l, _)| *l)
        .collect()
}

#[test]
fn grpc_messages_are_request_data() {
    let java = "\
class GreeterImpl extends GreeterGrpc.GreeterImplBase {
  public void sayHello(HelloRequest req, StreamObserver<HelloReply> out) {
    db.query(\"SELECT * FROM u WHERE n = '\" + req.getName() + \"'\");
    db.query(out.toString());
  }
}
class Plain {
  void helper(HelloRequest req) { db.query(req.getName()); }
}
";
    assert_eq!(reported("Java", "A.java", java), [3]);
    let kt = "\
class GreeterService : GreeterGrpcKt.GreeterCoroutineImplBase() {
    override suspend fun sayHello(request: HelloRequest): HelloReply {
        db.query(\"SELECT * FROM u WHERE n = '${request.name}'\")
        return HelloReply.getDefaultInstance()
    }
}
";
    assert_eq!(reported("Kotlin", "A.kt", kt), [3]);
    let cs = "\
public class GreeterService : Greeter.GreeterBase {
  public override Task<HelloReply> SayHello(HelloRequest request, ServerCallContext context) {
    db.query(\"SELECT * FROM u WHERE n = '\" + request.Name + \"'\");
    db.query(context.Peer);
    return null;
  }
}
";
    assert_eq!(reported("CSharp", "A.cs", cs), [3]);
    let py = "\
class Greeter(helloworld_pb2_grpc.GreeterServicer):
    def SayHello(self, request, context):
        db.query(\"SELECT * FROM u WHERE n = '%s'\" % request.name)
        db.query(context.peer())
";
    assert_eq!(reported("Python", "a.py", py), [3]);
    let go = "\
package main

func (s *server) SayHello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
\tdb.Query(\"SELECT * FROM u WHERE n = '\" + in.GetName() + \"'\")
\tdb.Query(fmt.Sprint(ctx))
\treturn nil, nil
}

func process(app App, ir *core.InternalRequest) {
\tdb.Query(ir.URL)
}

func (s *server) helper(ir *core.InternalRequest) {
\tdb.Query(ir.URL)
}

func handler(w http.ResponseWriter, r *http.Request) {
\tdb.Query(r.Method)
}
";
    assert_eq!(reported("Go", "a.go", go), [4]);
}
