use crate::{AUTHORIZATION_REQUIRED, AdmissionRefusal, AuthorityInput, ErrorCode};

/// A well-formed bundle document that is not the fixed Candidate. Callers vary
/// one field, so each test refuses for exactly the reason it names.
fn bundle_document(
    lifecycle: &str,
    definition_status: &str,
    session: bool,
    publication: bool,
) -> String {
    format!(
        concat!(
            r#"{{"artifactVersion":"licoarc.bundle.v1","wireId":"licoarc.protocol-line.v1","#,
            r#""generation":1,"lifecycle":"{}","definitionStatus":"{}","#,
            r#""sessionEligible":{},"publicationEligible":{},"#,
            r#""digestAlgorithm":"sha256","sources":{{}},"digest":"{}"}}"#,
        ),
        lifecycle,
        definition_status,
        session,
        publication,
        "0".repeat(64),
    )
}

fn candidate_document() -> String {
    bundle_document("Candidate", "COMPLETE", true, false)
}

fn refuse(bytes: &[u8]) -> AdmissionRefusal {
    AuthorityInput::new(bytes)
        .admit()
        .expect_err("input must be refused")
}

fn assert_refused_with(bytes: &[u8], detail: ErrorCode) {
    let refused = refuse(bytes);
    assert_eq!(refused.code(), AUTHORIZATION_REQUIRED);
    assert_eq!(refused.cause().code, detail);
    assert!(refused.to_string().starts_with(AUTHORIZATION_REQUIRED));
}

#[test]
fn empty_input_is_refused() {
    assert_refused_with(b"", ErrorCode::BoundExceeded);
}

#[test]
fn unknown_document_is_refused() {
    assert_refused_with(b"{}", ErrorCode::InvalidAuthorityInput);
    assert_refused_with(b"not a bundle", ErrorCode::InvalidAuthorityInput);
    assert_refused_with(
        br#"{"artifactVersion":"other.bundle.v9"}"#,
        ErrorCode::InvalidAuthorityInput,
    );
}

#[test]
fn unknown_fields_are_refused() {
    let document = candidate_document().replace(
        r#""digestAlgorithm""#,
        r#""extension":true,"digestAlgorithm""#,
    );
    assert_refused_with(document.as_bytes(), ErrorCode::InvalidAuthorityInput);
}

#[test]
fn a_published_or_partial_line_is_refused() {
    for (lifecycle, status, session, publication) in [
        ("Published", "COMPLETE", true, false),
        ("Candidate", "PARTIAL", true, false),
        ("Candidate", "COMPLETE", false, false),
        ("Candidate", "COMPLETE", true, true),
    ] {
        let document = bundle_document(lifecycle, status, session, publication);
        assert_refused_with(document.as_bytes(), ErrorCode::UnsupportedDefinition);
    }
}

#[test]
fn a_different_content_address_is_refused() {
    assert_refused_with(candidate_document().as_bytes(), ErrorCode::DigestMismatch);
}

#[test]
fn a_complete_bundle_document_is_still_refused_without_the_fixed_artifact() {
    // Bundle-shaped JSON with the fixed metadata is not the fixed artifact: only
    // the SDK's verification of the supplied bytes can admit a line.
    let refused = refuse(candidate_document().as_bytes());
    assert_eq!(refused.cause().code, ErrorCode::DigestMismatch);
    assert_eq!(refused.code(), AUTHORIZATION_REQUIRED);
}
