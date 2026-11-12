fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&segue_config::tooling::configuration_contract()).unwrap()
    );
}
