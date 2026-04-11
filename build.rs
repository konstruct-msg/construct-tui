use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = PathBuf::from("../construct-protos");

    let protos: Vec<PathBuf> = vec![
        proto_dir.join("services/auth_service.proto"),
        proto_dir.join("services/messaging_service.proto"),
        proto_dir.join("services/key_service.proto"),
        proto_dir.join("services/user_service.proto"),
    ];

    let includes: Vec<PathBuf> = vec![proto_dir.clone()];

    tonic_prost_build::configure()
        .build_server(false)
        .emit_rerun_if_changed(false)
        .type_attribute(".", "#[allow(clippy::large_enum_variant, clippy::enum_variant_names, clippy::doc_lazy_continuation, dead_code)]")
        .compile_protos(&protos, &includes)?;

    // Re-run if any proto changes
    println!("cargo:rerun-if-changed=../construct-protos");

    Ok(())
}
