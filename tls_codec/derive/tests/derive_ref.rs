use tls_codec::{
    Serialize, VLBytes,
    zero_copy::{DeserializeRef, RefT},
};
use tls_codec_derive::{DeserializeRef, TlsDeserializeBytes, TlsSerialize, TlsSize};

#[derive(Debug, PartialEq, Eq, DeserializeRef, TlsSerialize, TlsSize, TlsDeserializeBytes)]
struct HpkeCiphertext {
    kem_output: VLBytes,
    ciphertext: VLBytes,
}

#[derive(Debug, PartialEq, Eq, DeserializeRef, TlsSerialize, TlsSize, TlsDeserializeBytes)]
struct EncryptedGroupSecrets {
    new_member: VLBytes,
    encrypted_groupsecrets: HpkeCiphertext,
}

#[derive(Debug, DeserializeRef, TlsSerialize, TlsSize, TlsDeserializeBytes)]
struct Welcome {
    suite: u16,
    secrets: Vec<EncryptedGroupSecrets>,
    encrypted_group_info: VLBytes,
}

#[test]
fn build() {
    let welcome = Welcome {
        suite: 5,
        secrets: vec![EncryptedGroupSecrets {
            new_member: vec![0, 1, 2].into(),
            encrypted_groupsecrets: HpkeCiphertext {
                kem_output: vec![3, 4, 5].into(),
                ciphertext: vec![6, 7, 8].into(),
            },
        }],
        encrypted_group_info: vec![9, 0, 1].into(),
    };

    let serialized = welcome.tls_serialize_detached().unwrap();

    let (welcome_ref, remaining) = WelcomeRef::tls_deserialize_ref(&serialized).unwrap();
    assert!(remaining.is_empty());

    assert_eq!(welcome_ref.suite.as_type().unwrap(), welcome.suite);
    assert_eq!(welcome_ref.secrets.as_type().unwrap(), welcome.secrets);
}
