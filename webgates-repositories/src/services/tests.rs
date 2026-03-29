use std::sync::Arc;

use crate::account_repository::AccountRepository;
use crate::errors::{Error, RepositoriesError};
use crate::memory::account::MemoryAccountRepository;
use crate::memory::secret::MemorySecretRepository;
use crate::secret_repository::SecretRepository;
use crate::services::account_delete::AccountDeleteService;
use crate::services::account_insert::AccountInsertService;
use webgates_core::authz::AccessHierarchy;
use webgates_core::groups::Group;
use webgates_core::permissions::Permissions;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
enum TestRole {
    #[default]
    User,
    Admin,
}

impl AccessHierarchy for TestRole {}

#[tokio::test]
async fn account_insert_service_stores_account_and_secret() {
    let account_repository = Arc::new(MemoryAccountRepository::<TestRole, Group>::default());
    let secret_repository = Arc::new(match MemorySecretRepository::new_with_argon2_hasher() {
        Ok(repository) => repository,
        Err(error) => panic!("hasher setup should succeed: {}", error),
    });

    let mut permissions = Permissions::new();
    permissions.grant("projects:read");

    let created: webgates_core::accounts::Account<TestRole, Group> =
        match AccountInsertService::insert("user@example.com", "password-123")
            .with_roles(vec![TestRole::User, TestRole::Admin])
            .with_groups(vec![Group::new("engineering")])
            .with_permissions(permissions.clone())
            .into_repositories(
                Arc::clone(&account_repository),
                Arc::clone(&secret_repository),
            )
            .await
        {
            Ok(Some(account)) => account,
            Ok(None) => panic!("account should be returned"),
            Err(error) => panic!("insert should succeed: {}", error),
        };

    assert_eq!(created.user_id, "user@example.com");
    assert_eq!(created.roles, vec![TestRole::User, TestRole::Admin]);
    assert_eq!(created.groups, vec![Group::new("engineering")]);
    assert_eq!(created.permissions, permissions);

    let stored_account: webgates_core::accounts::Account<TestRole, Group> = match account_repository
        .query_account_by_id(&created.account_id)
        .await
    {
        Ok(Some(account)) => account,
        Ok(None) => panic!("stored account should exist"),
        Err(error) => panic!("account lookup should succeed: {}", error),
    };
    assert_eq!(stored_account, created);

    let removed_secret = match secret_repository.delete_secret(&created.account_id).await {
        Ok(Some(secret)) => secret,
        Ok(None) => panic!("secret should exist"),
        Err(error) => panic!("secret lookup via delete should succeed: {}", error),
    };
    assert_eq!(removed_secret.account_id, created.account_id);
}

#[tokio::test]
async fn account_delete_service_removes_account_and_secret() {
    let account_repository = Arc::new(MemoryAccountRepository::<TestRole, Group>::default());
    let secret_repository = Arc::new(match MemorySecretRepository::new_with_argon2_hasher() {
        Ok(repository) => repository,
        Err(error) => panic!("hasher setup should succeed: {}", error),
    });

    let account = match AccountInsertService::insert("deleteme@example.com", "password-123")
        .into_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secret_repository),
        )
        .await
    {
        Ok(Some(account)) => account,
        Ok(None) => panic!("account should be returned"),
        Err(error) => panic!("insert should succeed: {}", error),
    };

    if let Err(error) = AccountDeleteService::delete(account.clone())
        .from_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secret_repository),
        )
        .await
    {
        panic!("delete should succeed: {}", error);
    }

    let stored_account: Option<webgates_core::accounts::Account<TestRole, Group>> =
        match account_repository
            .query_account_by_id(&account.account_id)
            .await
        {
            Ok(account) => account,
            Err(error) => panic!("account lookup should succeed: {}", error),
        };
    assert!(stored_account.is_none());

    let stored_secret = match secret_repository.delete_secret(&account.account_id).await {
        Ok(secret) => secret,
        Err(error) => panic!("secret lookup via delete should succeed: {}", error),
    };
    assert!(stored_secret.is_none());
}

#[tokio::test]
async fn account_delete_service_returns_not_found_when_secret_is_missing() {
    let account_repository = Arc::new(MemoryAccountRepository::<TestRole, Group>::default());
    let secret_repository = Arc::new(match MemorySecretRepository::new_with_argon2_hasher() {
        Ok(repository) => repository,
        Err(error) => panic!("hasher setup should succeed: {}", error),
    });

    let account = match AccountInsertService::insert("missing-secret@example.com", "password-123")
        .into_repositories(
            Arc::clone(&account_repository),
            Arc::clone(&secret_repository),
        )
        .await
    {
        Ok(Some(account)) => account,
        Ok(None) => panic!("account should be returned"),
        Err(error) => panic!("insert should succeed: {}", error),
    };

    let removed_secret = match secret_repository.delete_secret(&account.account_id).await {
        Ok(secret) => secret,
        Err(error) => panic!("secret delete should succeed: {}", error),
    };
    assert!(removed_secret.is_some());

    let error = match AccountDeleteService::delete(account.clone())
        .from_repositories(account_repository, secret_repository)
        .await
    {
        Ok(()) => panic!("delete should fail when secret is missing"),
        Err(error) => error,
    };

    match error {
        Error::Repositories(RepositoriesError::NotFound { repository, key }) => {
            assert_eq!(repository.to_string(), "secret");
            assert_eq!(key, Some(account.account_id.to_string()));
        }
        other => panic!("unexpected error: {other}"),
    }
}
