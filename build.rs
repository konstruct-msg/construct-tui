use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = PathBuf::from("../construct-protos");

    let protos = [
        "services/auth_service.proto",
        "services/messaging_service.proto",
        "services/key_service.proto",
        "services/user_service.proto",
    ];

    let includes = [
        proto_dir.to_str().unwrap(),
    ];

    tonic_build::configure()
        .build_server(false)
        .compile_protos(
            &protos.map(|p| proto_dir.join(p)),
            &includes,
        )?;

    // Re-run if any proto changes
    println!("cargo:rerun-if-changed=../construct-protos");

    Ok(())
}
