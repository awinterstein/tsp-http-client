use cmpv2::status::PkiStatus;
use cms::signed_data::SignedData;
use der::asn1::OctetString;
use der::oid::ObjectIdentifier;
use der::oid::db::rfc5912::{ID_SHA_224, ID_SHA_256, ID_SHA_384, ID_SHA_512};
use der::{Any, Decode, Encode};
use rand::Rng;
use spki::AlgorithmIdentifier;
use x509_tsp;
use x509_tsp::{MessageImprint, TimeStampReq, TimeStampResp, TspVersion, TstInfo};

/// Wrapper around the TimeStampReq type from the x509-tsp crate to allow for easier handling of timestamp requests.
pub struct TimeStampRequest {
    /// The digest of the data to be timestamped, represented as a byte vector.
    digest: Vec<u8>,

    /// The hash algorithm used for the digest (determined from the digest length).
    hash_algorithm: ObjectIdentifier,

    /// The ASN.1 representation of the timestamp request as provided by the x509-tsp crate.
    asn_request_data: TimeStampReq,
}

impl TimeStampRequest {
    pub fn new(digest: Vec<u8>) -> Result<Self, Box<dyn std::error::Error>> {
        // Select matching hash algorithm (SHA) based on the length of the digest.
        let hash_algorithm = match digest.len() {
            28 => Ok(ID_SHA_224),
            32 => Ok(ID_SHA_256),
            48 => Ok(ID_SHA_384),
            64 => Ok(ID_SHA_512),
            _ => Err(crate::Error::InvalidDigest),
        }?;

        // A random nonce is generated to ensure uniqueness of the timestamp request.
        let random_nonce: [u8; 8] = rand::rng().random();

        // Create the ASN.1 representation of the timestamp request.
        let asn_request_data = TimeStampReq {
            version: TspVersion::V1,
            req_policy: None,
            message_imprint: MessageImprint {
                hash_algorithm: AlgorithmIdentifier::<Any> {
                    oid: hash_algorithm,
                    parameters: None,
                },
                hashed_message: OctetString::new(digest.clone())?,
            },
            nonce: Some(der::asn1::Int::new(&random_nonce)?),
            cert_req: true,
            extensions: None,
        };

        Ok(TimeStampRequest {
            digest,
            hash_algorithm,
            asn_request_data,
        })
    }

    /// Converts the timestamp request to its ASN.1 DER encoded representation.
    pub fn to_der(&self) -> Result<Vec<u8>, der::Error> {
        self.asn_request_data.to_der()
    }

    /// Returns the digest of the data to be timestamped.
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    /// Returns the hash algorithm (length of SHA) used for the digest.
    pub fn hash_algorithm(&self) -> &ObjectIdentifier {
        &self.hash_algorithm
    }

    /// Returns the ASN.1 representation of nonce (random number) used in the request.
    pub fn nonce(&self) -> &Option<der::asn1::Int> {
        &self.asn_request_data.nonce
    }
}

/// Wrapper around the response from a timestamp server, providing methods to access and verify the signed timestamp.
///
/// Right now, the timestamp response is only verified regarding the data it contains, not the signature itself. This
/// might be added in the future.
pub struct TimeStampResponse {
    /// The raw DER encoded response data from the timestamp server.
    data: Vec<u8>,
}

impl TimeStampResponse {
    /// Creates a new `TimeStampResponse` from the provided DER encoded data.
    ///
    /// * `data`: The raw bytes (ASN.1 DER encoded) of the timestamp response.
    ///
    /// There is no check done, whether the given data is actually a DER encoded timestamp response. In case of invalid
    /// data a call to the `verify` method will indicate an error then.
    pub fn new(data: Vec<u8>) -> Self {
        TimeStampResponse { data }
    }

    /// Returns the raw DER encoded data of the timestamp response.
    ///
    /// This is the same data that was provided when creating the `TimeStampResponse` instance. Hence, to ensure that
    /// the data is valid, you should call the `verify` method before using this data.
    pub fn as_der_encoded(&self) -> &[u8] {
        &self.data
    }

    /// Verifies the timestamp response against the original timestamp request.
    ///
    /// This includes checking the version, hash algorithm, and the message imprint to ensure they match the original
    /// data. This is not a complete check regarding the RFC 3161 standard, but it covers the most important aspects
    /// for basic usage.
    ///
    /// Right now, the timestamp response is only verified regarding the data it contains, not the signature itself. This
    /// might be added in the future.
    ///
    /// * `request`: The original timestamp request that was sent to the server.
    pub fn verify(&self, request: &TimeStampRequest) -> Result<(), Box<dyn std::error::Error>> {
        let signed_data: SignedData = SignedData::from_der(&self.content()?)?;
        let encap = signed_data
            .encap_content_info
            .econtent
            .ok_or(crate::Error::InvalidServerResponse)?;
        let tst = TstInfo::from_der(&encap.value())?;

        // The version must always be V1 according to RFC 3161
        if tst.version != TspVersion::V1 {
            return Err(Box::new(crate::Error::InvalidServerResponse));
        }

        // The nonce must match the one generated when the creating the query
        if tst.nonce != *request.nonce() {
            return Err(Box::new(crate::Error::InvalidServerResponse));
        }

        // The hash algorithm must match the one used to create the query
        if tst.message_imprint.hash_algorithm.oid != *request.hash_algorithm() {
            return Err(Box::new(crate::Error::InvalidServerResponse));
        }

        // The message imprint must be present and match the original data
        if tst.message_imprint.hashed_message.as_bytes() != request.digest() {
            return Err(Box::new(crate::Error::DigestMismatch));
        }

        Ok(())
    }

    /// Extracts and returns the date and time of the timestamp.
    ///
    /// The result is given in the UTC timezone as a `chrono::DateTime<Utc>`.
    pub fn datetime(&self) -> Result<chrono::DateTime<chrono::Utc>, Box<dyn std::error::Error>> {
        let signed_data: SignedData = SignedData::from_der(&self.content()?)?;
        let encap = signed_data
            .encap_content_info
            .econtent
            .ok_or(crate::Error::InvalidServerResponse)?;
        let tst = TstInfo::from_der(&encap.value())?;

        let unix_duration = tst.gen_time.to_unix_duration();

        Ok(chrono::DateTime::from_timestamp(
            unix_duration.as_secs() as i64,
            unix_duration.subsec_nanos(),
        )
        .ok_or(crate::Error::InvalidServerResponse)?)
    }

    fn content(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let timestamp_response = TimeStampResp::from_der(&self.data)?;

        // Check if the response status is accepted and if not, try to extract the status string to return as error information.
        if timestamp_response.status.status != PkiStatus::Accepted {
            let status_string = timestamp_response
                .status
                .status_string
                .and_then(|s| s.first().map(|s| s.to_string()));
            return Err(Box::new(crate::Error::RequestNotAccepted(status_string)));
        }

        let content = timestamp_response
            .time_stamp_token
            .ok_or(crate::Error::InvalidServerResponse)?;
        let content = content.content;
        Ok(content.to_der()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

    // Define request and response data for the response checking. The response was generated by a TSA based on the
    // digest and nonce that is specified here.
    const TEST_REQUEST_DIGEST: &str =
        "3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04";
    const TEST_REQUEST_NONCE: u64 = 0x769A758306377DA6;
    const TEST_RESPONSE: &str = "308211ab3003020100308211a206092a864886f70d010702a08211933082118f020103310f300d060960864801650304020205003082010e060b2a864886f70d0109100104a081fe0481fb3081f8020101060604008f670101302f300b060960864801650304020104203f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04021500d721db8a51849625c050ea3ffd8f701aeeca8cad180f32303235303631353036353235375a30030201010208769a758306377da6a063a461305f310b3009060355040613024553311c301a060355040a13135365637469676f20284575726f70652920534c3132303006035504030c295365637469676f205175616c69666965642054696d65205374616d70696e67205369676e6572202333a11e301c06082b06010505070103010100040d300b30090607040081975e0101a0820c8530820655308204bda0030201020210660a98f14e15b2ec83c59581bed2e038300d06092a864886f70d01010c0500305c310b3009060355040613024553311c301a060355040a13135365637469676f20284575726f70652920534c312f302d060355040313265365637469676f205175616c69666965642054696d65205374616d70696e6720434120523335301e170d3233303530333030303030305a170d3334303830323233353935395a305f310b3009060355040613024553311c301a060355040a13135365637469676f20284575726f70652920534c3132303006035504030c295365637469676f205175616c69666965642054696d65205374616d70696e67205369676e657220233330820222300d06092a864886f70d01010105000382020f003082020a02820201009877066156c4247c7d84b2d4a6a053e517d291679f8e405b8e111f9f15ab3f0a98b828d79ad453e57386ca3decef2fb11e423ddd72ad020123e3b2d21d672b79d0bc95960926cf0d647d280897086cf2ad4918899c005eb32a84dd75ae9ad777662901b47914bcb20a5e115f89c81d2c4ecc4a7d5f4f3daf6aea788ac67ce6fbf38b2ad30c2fec5920dd47a4409c509c9a0e4d2d725b5410f2702cc2bf0e9593e46bd2eee85d63f625c12ddf0ecfc230c4a053245e483770a834b319c3510f5dc676d9dbd872fbdd7d69b90fab1dfa76cfdda423df8b1fe0e77d1911fd2e842ba6263396cd0bf1227f807ab343a2f71acafc46cde1e03a4bd463352682b7ee2bd9eb08dffb337a223494d5eb9762bfe0cf1911ce31e23e52de0cd067c406e22cb0614437e97e2b62d769fdf91592beb74b328493bbfc47909a2b35c9742da266c3bb03b8a9d47adc62257668ce2a4f35ce9796bf0965699bfb134b2a9633485b33dbcc5f43e90933df97cc3a79b9fdf3c489f080a8d965efc1ce776f597ce36dad608c48ee6a8dd6c46021d84cdd0b568c24d7f986cff6490b6b502a830fc0d85bd50636382af224b977d70165589611e7e125b14c2132c5a395fc938cfb099d3e57cd7dd45dbc40c0456d9904a447e781fe9d1550d8e9081dbac400b20e78081730fc3a83c014ddeb77b1564d885abe9dc7a5eddfebc4d24b666c19dbfd96150203010001a382018e3082018a301f0603551d2304183016801461003f77d9ffea39d291a51cbe9d35c7785ea467301d0603551d0e0416041437510f19bd26dfe6d54ad061b1723d02fc184b16300e0603551d0f0101ff0404030206c0300c0603551d130101ff0402300030160603551d250101ff040c300a06082b0601050507030830440603551d20043d303b3039060b2b06010401b23101020109302a302806082b06010505070201161c68747470733a2f2f7365637469676f2e636f6d2f6549444153435053304d0603551d1f044630443042a040a03e863c687474703a2f2f63726c2e7365637469676f2e636f6d2f5365637469676f5175616c696669656454696d655374616d70696e6743415233352e63726c307d06082b060105050701010471306f304806082b06010505073002863c687474703a2f2f6372742e7365637469676f2e636f6d2f5365637469676f5175616c696669656454696d655374616d70696e6743415233352e637274302306082b060105050730018617687474703a2f2f6f6373702e7365637469676f2e636f6d300d06092a864886f70d01010c050003820181001af6c65413f6c1f4b71e98f7e6262d3293a4900eb6e29c9079c0ec86b0a03e2bed97569fe5e608948bbf5534396aabe812d657039755f97c6dbcabac0e9cc9e6ee16eda4c04ebfb786b23fdd0d5b0611083560595fcd9ac6572d787ab126ef0f65ca646e1212c62ff60308920da397f2b2601ae52d95a072618c468533590682c38b2fc89f6d43bae455f01486a609df78f3ae9b0afb4044ae62d939588729051a6b9af7908eb72b8e32fc7f20075609ef5f6553b10274b0684e36da5e415486a2d6f8e339e7170ae7f9f79b838b7db64a45e8c7514edeef56480e5c07df762bb71994841c7539ace166cbea64e515a4d4d9beae4fc375b7089ddd57e7eafa32709105e31dd376233e6db1fe793702f202b7abc1087fd3b5d5c5fbfc16a337d221177ccda4167783fd5d381513b52f9ff7925802f787fe16362a05cc04a0a29bae2a41bb5e0d59b4f9b546cb1083d877700a95ec9454ae90759db56b8ac4fb596fbfac1b37da0c5e7888217572c1f6075374998e1ecee056cbac027609fb275c3082062830820410a00302010202100cda8301d3f3280e71cdb028a352c65b300d06092a864886f70d01010c0500305e310b3009060355040613024553311c301a060355040a13135365637469676f20284575726f70652920534c3131302f060355040313285365637469676f205175616c69666965642054696d65205374616d70696e6720526f6f7420523435301e170d3230313030353030303030305a170d3335313030343233353935395a305c310b3009060355040613024553311c301a060355040a13135365637469676f20284575726f70652920534c312f302d060355040313265365637469676f205175616c69666965642054696d65205374616d70696e6720434120523335308201a2300d06092a864886f70d01010105000382018f003082018a028201810081978ee6386cc707e337cc9caca223c6dcd581b5afc90ccca1c6154bff394b9be30af32d03d0b48c18b225873e98369b9302cca49eba40c6a9ab38aa052517fea1b9b1faa13805d90422911130da742b57c3c54d921513c94e6da642babc309f8969a499942f55a8a8bc4764296bbd348451896c175655a835dee63c8a4b83c173cddd2eba049fa9ee21306113ecf90c60aff7b1d5dd484c70824cb8a4d9990aed8948c7d28ce0de59f354f2364fccb7035ec03f25896cb9ac7f7c1a639e2f206ab4ac074b2db6f03d15065981d95385bb9e48097c888b4087daf9dd13ff5146e323c95d358ad709cb642ea50d751b7d948ec683f67900b6d20ecccfa8d19463dd61026a55a2066a33eb11462e88d27e02e6109cc0cc22dc0caabbfc063ca0b44960ff09bd960d4604ae09da06ec658e0f6266559054de72872402c1744dd7fb9ec74c6d3c394daedf172343a21752ab48e00772f5f57f128d34180bdf5b78263544f53707d646d3666b97aca23d53912db6d42e2a166afc0ae7a2f44cb743cb0203010001a38201623082015e301f0603551d230418301680145981a8c38564e7e344a46952269453f63b0deede301d0603551d0e0416041461003f77d9ffea39d291a51cbe9d35c7785ea467300e0603551d0f0101ff04040302018630120603551d130101ff040830060101ff02010030130603551d25040c300a06082b0601050507030830110603551d20040a300830060604551d2000304f0603551d1f044830463044a042a040863e687474703a2f2f63726c2e7365637469676f2e636f6d2f5365637469676f5175616c696669656454696d655374616d70696e67526f6f745234352e63726c307f06082b0601050507010104733071304a06082b06010505073002863e687474703a2f2f6372742e7365637469676f2e636f6d2f5365637469676f5175616c696669656454696d655374616d70696e67526f6f745234352e637274302306082b060105050730018617687474703a2f2f6f6373702e7365637469676f2e636f6d300d06092a864886f70d01010c0500038202010018a0fb7652767a8daca314c122a0644c712bc3a1e6566add8ca8e2bf2573c8a794d55f465332ca1b9630231d73b92894f0c836bf06f831999223bdbbf020590049c6c89ef8e5ef3374598b6f837f23d1ef60687fe181c25841813a4245d958ae72d7f826cce0c868048b110a0ea10defdb0bcb91e55321106e45c44a161e3c03c7d08762a16a2be30756c3826f71682decdf3c283edb8cd7f675f40210470b4ed6dc56d834eb174bec1abde36cc210e7804b7b557de7f57ef2cc8eb20c3aedb28c25ea2bb423698a98899149e4500a3e2a1974729661edb65d0aed92f07a90190892d753ed61bfb682e4350b332b8c3c995152171d15ee1f7b9e1d50f55b4eb74b3fd8026c84f3add0a044d19e850fcf1e37aa59d7527fd68c1ad31e35f813c185c4121bb8d5b7d5429a5dec68688eefced5003333265755af9c1bf661a63bc981c96e9521113e54083263b0180cb2717edcef8e9b5540f33adc792296ac626fb59f4c01ea2dbf2010466625cd87722b75d22daaf319602c3f000d672432485054a8c9b88d51cd342c84e1470d30be66fb80b6143eec49d37e706c55740eb52aa8ee3e8d59ae920280c7a17c633c18bddb1c6680c78ef5c99fd644ca3e074d60bc8270e7176abc832e94506c9928af36c42542eaea2e77710b1d4db7aee603d8a07fb1522b8e1b34cc3ed661d8824930638f90070b1308191a4748cdfe22f7b5318203dc308203d80201013070305c310b3009060355040613024553311c301a060355040a13135365637469676f20284575726f70652920534c312f302d060355040313265365637469676f205175616c69666965642054696d65205374616d70696e67204341205233350210660a98f14e15b2ec83c59581bed2e038300d06096086480165030402020500a082013d301a06092a864886f70d010903310d060b2a864886f70d0109100104301c06092a864886f70d010905310f170d3235303631353036353235375a303f06092a864886f70d010904313204306fb54d0a7c20bad4b5916d16a3b901c0753d74a1f65a53e4848b80e068cf42eed691a6e7f6ada1758eb82da4a6c7c2883081bf060b2a864886f70d010910020c3181af3081ac3081a930160414b96e48620d86e289b6a6372463b112e2665788bd30818e04141d6318b5b7d9ba360d757ac955881bf17c75076630763062a460305e310b3009060355040613024553311c301a060355040a13135365637469676f20284575726f70652920534c3131302f060355040313285365637469676f205175616c69666965642054696d65205374616d70696e6720526f6f742052343502100cda8301d3f3280e71cdb028a352c65b300d06092a864886f70d010101050004820200169d2289f313cfdefc7e51bb36d3db88e4cf1083d7b1f6ab6238edb3d42350631890be2e4967bd6966af19c5de394fee64770d7ebf552499be7d89a489f8e01d79b74035154c09fa22cce778d0d7b288acd8c63bad836b23579341d93380416510c2ea1034ff467e30f311a25b9b274147cd89b28411747e3cfb7313de697b91f2e900011cd2b01612a9ab98f3677bd1f0e6016403f8ac08e329b3719946f3af70cad4f171e034a19b008c1f36d371051c682bc8a88964032ce2e2a1184ecab4351e1b7ee533056c329c3caa6048d7cc6d90bce02cb9ea435066704358946b3c54656ac64edca64fe40498c6fbb8f062f646aa2b397fe776a5bbeb4adad3413a39c2c717b3b43e29bc6f81d78370baa8ec33314e9da4c79ea22f2bb650b921d9d924a2ed49a983c06f14543e8f510455dbf8c2d0bc07f8b6e8677c6b9e0268047f8f2eaa14422d93514b8c7a35e625788f980818528edb664f1d05c90a054bd6672b9d1a39a83fe3172cf0f51130a57dc1c3675d7e0527d2f6c672af3aacd31f389bf3422ccfe61788cecb1c6df7ae711053c87ffc05b5063ed7a3733583cbae3c5fc5c45d62bd92cce52ebd44ac230866fc510b1cc1b2c5c3105b661cbee4b7edd3ddd89e46c2a6fb963b5665583d7a6d7b718ebde357dc5776a760ce0d2a8a9298f5d5dd4275676679ce998b7d67bb3495e1728927a355db608c1efd3a04aa";

    fn create_test_request(digest: &str) -> TimeStampRequest {
        let mut request = TimeStampRequest::new(hex::decode(digest).unwrap()).unwrap();

        // we need to replace the randomly generated nonce with the none that was used at the original request
        request.asn_request_data.nonce =
            Some(der::asn1::Int::new(&TEST_REQUEST_NONCE.to_be_bytes()).unwrap());

        request
    }

    fn assert_error_equals<T>(result: Result<T, Box<dyn std::error::Error>>, error: crate::Error) {
        assert_eq!(
            *result
                .err()
                .unwrap()
                .downcast_ref::<crate::Error>()
                .unwrap(),
            error
        );
    }

    #[test]
    fn request_valid_digest_lengths_accepted() {
        let req = TimeStampRequest::new(Sha224::digest(b"hello world").to_vec()).unwrap();
        assert_eq!(*req.hash_algorithm(), ID_SHA_224);

        let req = TimeStampRequest::new(Sha256::digest(b"hello world").to_vec()).unwrap();
        assert_eq!(*req.hash_algorithm(), ID_SHA_256);

        let req = TimeStampRequest::new(Sha384::digest(b"hello world").to_vec()).unwrap();
        assert_eq!(*req.hash_algorithm(), ID_SHA_384);

        let req = TimeStampRequest::new(Sha512::digest(b"hello world").to_vec()).unwrap();
        assert_eq!(*req.hash_algorithm(), ID_SHA_512);
    }

    #[test]
    fn request_invalid_digest_lengths_rejected() {
        // just to ensure that the following checks for invalid lengths will actually catch errors due to the length
        assert!(TimeStampRequest::new(vec![1; 512 / 8]).is_ok());

        // close to SHA-512
        assert_error_equals(
            TimeStampRequest::new(vec![1; (512 / 8) - 1]),
            crate::Error::InvalidDigest,
        );
        assert_error_equals(
            TimeStampRequest::new(vec![1; (512 / 8) - 2]),
            crate::Error::InvalidDigest,
        );

        // large value (too large for a digest)
        assert_error_equals(
            TimeStampRequest::new(vec![1; 100000]),
            crate::Error::InvalidDigest,
        );
    }

    #[test]
    fn request_nonce_is_different_for_multiple_requests() {
        let req1 = TimeStampRequest::new(Sha256::digest(b"message data").to_vec()).unwrap();
        let nonce1 = req1.nonce();

        let req2 = TimeStampRequest::new(Sha256::digest(b"message data").to_vec()).unwrap();
        let nonce2 = req2.nonce();

        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn request_der_encoding_as_expected() {
        let digest = Sha256::digest(b"message data").to_vec();
        let req = TimeStampRequest::new(digest.clone()).unwrap();

        // retrieve DER encoding from the object and read it into an object from the x509_tsp crate to check its contents
        let x509_req = TimeStampReq::from_der(&req.to_der().unwrap()).unwrap();
        assert_eq!(x509_req.version, TspVersion::V1);
        assert_eq!(x509_req.cert_req, true);
        assert_eq!(x509_req.extensions, None);
        assert_eq!(x509_req.req_policy, None);
        assert_eq!(
            x509_req.message_imprint.hash_algorithm.oid,
            *req.hash_algorithm()
        );
        assert_eq!(
            x509_req.message_imprint.hashed_message,
            der::asn1::OctetString::new(digest).unwrap()
        );
        assert_eq!(x509_req.nonce, *req.nonce());
    }

    #[test]
    fn response_successful_verification() {
        let request = create_test_request(TEST_REQUEST_DIGEST);
        let response = TimeStampResponse::new(hex::decode(TEST_RESPONSE).unwrap());

        assert!(response.verify(&request).is_ok());
    }

    #[test]
    fn response_rejected_on_digest_mismatch() {
        // create a request with a different digest than it is in the test response message
        let request =
            create_test_request("695f2eca5e11109e3bd5a237b33688e0d8273ad74b453728833a0ffc2c22473d");
        let response = TimeStampResponse::new(hex::decode(TEST_RESPONSE).unwrap());
        assert_error_equals(response.verify(&request), crate::Error::DigestMismatch);
    }

    #[test]
    fn response_rejected_on_nonce_mismatch() {
        // creating a new request object, generates a new nonce which should not match the original one then
        let request = TimeStampRequest::new(hex::decode(TEST_REQUEST_DIGEST).unwrap()).unwrap();

        let response = TimeStampResponse::new(hex::decode(TEST_RESPONSE).unwrap());
        assert_error_equals(
            response.verify(&request),
            crate::Error::InvalidServerResponse,
        );
    }

    #[test]
    fn response_date_extraction() {
        let response = TimeStampResponse::new(hex::decode(TEST_RESPONSE).unwrap());

        // check that the datetime function returns the same values as they were extracted with OpenSSL from the response
        assert_eq!(
            response.datetime().unwrap(),
            chrono::NaiveDate::from_ymd_opt(2025, 6, 15)
                .unwrap()
                .and_hms_opt(6, 52, 57)
                .unwrap()
                .and_utc()
        );
    }
}
