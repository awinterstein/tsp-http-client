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
