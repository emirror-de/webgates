use std::sync::Arc;

use webgates::accounts::Account;
use webgates::authz::access_policy::AccessPolicy;
use webgates::groups::Group;
use webgates::roles::Role;
use webgates_axum::gate::Gate;
use webgates_codecs::jwt::{JsonWebToken, JsonWebTokenOptions, JwtClaims};

type Claims = JwtClaims<Account<Role, Group>>;

/// Verifies that downstream callers can use every bearer builder transition.
#[test]
fn bearer_builder_methods_are_available_from_the_public_entry_point() {
    let codec = Arc::new(JsonWebToken::<Claims>::new_with_options(
        JsonWebTokenOptions::generate_for_testing().expect("test key generation should succeed"),
    ));

    let _jwt_policy = Gate::bearer::<_, Role, Group>("service", Arc::clone(&codec))
        .with_policy(AccessPolicy::<Role, Group>::require_role(Role::Admin));
    let _jwt_login = Gate::bearer::<_, Role, Group>("service", Arc::clone(&codec)).require_login();
    let _jwt_optional = Gate::bearer::<_, Role, Group>("service", Arc::clone(&codec))
        .allow_anonymous_with_optional_user();
    let _static_strict = Gate::static_bearer("token");
    let _static_optional = Gate::static_bearer("token").allow_anonymous_with_optional_user();
}
