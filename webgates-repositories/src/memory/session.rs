use webgates_sessions::memory::InMemorySessionRepository;

/// In-memory session repository implementation for `webgates-sessions`.
///
/// This type aliases the framework-agnostic in-memory session repository from
/// `webgates-sessions` so applications using `webgates-repositories` can keep a
/// consistent backend import surface for development and testing.
pub type MemorySessionRepository = InMemorySessionRepository;
