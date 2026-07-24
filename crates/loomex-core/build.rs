fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "../../proto/loomex/runner/v1/runner_stream.proto";

    // Do not depend on a mutable system protoc installation. The runner is distributed as a
    // self-contained plugin runtime and must build reproducibly on developer and CI machines.
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);

    println!("cargo:rerun-if-changed={proto}");

    tonic_build::configure()
        .build_server(false)
        .compile_protos(&[proto], &["../../proto"])?;

    Ok(())
}
