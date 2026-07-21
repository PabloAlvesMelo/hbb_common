// Ferramenta de 1x uso: gera um par Ed25519 (sodiumoxide::crypto::sign) no
// mesmo formato que read_custom_client() (src/common.rs) espera pra
// verificar custom.txt. Nao e chamado por nenhum outro lugar do produto -
// so uma utilidade de linha de comando, ver rustdesk-server/doc/
// 08_PLANO_DE_TRABALHO.md ("versao basica incoming-only").
use sodiumoxide::crypto::sign;

#[allow(deprecated)]
fn b64(input: impl AsRef<[u8]>) -> String {
    base64::encode(input)
}

fn main() {
    sodiumoxide::init().unwrap();
    let (pk, sk) = sign::gen_keypair();
    println!("PUBLIC (cole em src/common.rs, const KEY):\n{}", b64(pk.0));
    println!("PRIVATE (guardar em local seguro, NUNCA commitar):\n{}", b64(sk.0));
}
