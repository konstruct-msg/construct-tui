use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Allow CI / other environments to specify the protos directory via env var.
    // Falls back to the sibling-repo convention for local development.
    let proto_dir = std::env::var("CONSTRUCT_PROTOS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("../construct-protos"));

    let protos: Vec<PathBuf> = vec![
        proto_dir.join("services/auth_service.proto"),
        proto_dir.join("services/messaging_service.proto"),
        proto_dir.join("services/key_service.proto"),
        proto_dir.join("services/user_service.proto"),
        proto_dir.join("messaging/content.proto"),
    ];

    let includes: Vec<PathBuf> = vec![proto_dir.clone()];

    tonic_prost_build::configure()
        .build_server(false)
        .emit_rerun_if_changed(false)
        .type_attribute(".", "#[allow(clippy::large_enum_variant, clippy::enum_variant_names, clippy::doc_lazy_continuation, dead_code)]")
        .compile_protos(&protos, &includes)?;

    println!("cargo:rerun-if-changed={}", proto_dir.display());
    println!("cargo:rerun-if-env-changed=CONSTRUCT_PROTOS_DIR");

    Ok(())
}
