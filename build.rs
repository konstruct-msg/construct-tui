use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = PathBuf::from("../construct-protos");

    let protos = [
        "services/auth_service.proto",
        "services/messaging_service.proto",
        "services/key_service.proto",
        "services/user_service.proto",
    ];

    let includes = [proto_dir.to_str().unwrap()];

    tonic_build::configure()
        .build_server(false)
        // Suppress clippy warnings in generated protobuf code (large enums, naming, docs).
        .emit_rerun_if_changed(false)
        .type_attribute(".", "#[allow(clippy::large_enum_variant, clippy::enum_variant_names, clippy::doc_lazy_continuation)]")
        .compile_protos(&protos.map(|p| proto_dir.join(p)), &includes)?;

    // Re-run if any proto changes
    println!("cargo:rerun-if-changed=../construct-protos");

    Ok(())
}
