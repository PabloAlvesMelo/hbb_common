// Ferramenta: monta e assina um custom.txt pro mecanismo read_custom_client()
// (rustdesk/src/common.rs). Nao faz parte do produto - so uma utilidade de
// linha de comando, ver rustdesk-server/doc/08_PLANO_DE_TRABALHO.md
// ("versao basica incoming-only").
//
// Uso:
//   cargo run --example sign_custom_client -- <payload.json> <saida custom.txt> [chave privada, opcional]
//
// Sem o 3o argumento, le a chave privada de ~/.sgconnect-keys/custom-client-signing.key
// (linha "PRIVATE_KEY_BASE64=..."), o mesmo arquivo gerado por
// gen_custom_client_key.rs - NUNCA commitar essa chave em nenhum repo.
use sodiumoxide::crypto::sign;
use std::io::Write;

#[allow(deprecated)]
fn b64_decode(s: &str) -> Vec<u8> {
    base64::decode(s.trim()).expect("chave/base64 invalido")
}
#[allow(deprecated)]
fn b64_encode(data: &[u8]) -> String {
    base64::encode(data)
}

fn read_secret_key_from_default_file() -> String {
    let home = std::env::var("HOME").expect("HOME nao definido");
    let path = format!("{home}/.sgconnect-keys/custom-client-signing.key");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("nao consegui ler {path}"));
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("PRIVATE_KEY_BASE64=") {
            return v.trim().to_owned();
        }
    }
    panic!("PRIVATE_KEY_BASE64 nao encontrada em {path}");
}

fn main() {
    sodiumoxide::init().unwrap();
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("uso: sign_custom_client <payload.json> <saida custom.txt> [chave privada base64]");
        std::process::exit(1);
    }
    let payload_path = &args[1];
    let output_path = &args[2];
    let sk_b64 = if args.len() >= 4 {
        args[3].clone()
    } else {
        read_secret_key_from_default_file()
    };

    let payload = std::fs::read(payload_path)
        .unwrap_or_else(|_| panic!("nao consegui ler {payload_path}"));
    // Validacao minima: precisa ser JSON valido (read_custom_client faz parse
    // como HashMap<String, Value> depois de verificar a assinatura).
    let _: std::collections::HashMap<String, serde_json::Value> =
        serde_json::from_slice(&payload).expect("payload nao e um JSON de objeto valido");

    let sk_bytes = b64_decode(&sk_b64);
    let sk = sign::SecretKey::from_slice(&sk_bytes).expect("chave privada invalida");

    let signed = sign::sign(&payload, &sk);
    let out = b64_encode(&signed);

    let mut f = std::fs::File::create(output_path)
        .unwrap_or_else(|_| panic!("nao consegui criar {output_path}"));
    f.write_all(out.as_bytes()).unwrap();

    println!("OK: {output_path} gerado ({} bytes assinados, {} bytes base64)", signed.len(), out.len());
}
