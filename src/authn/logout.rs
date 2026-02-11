/// Application service for handling user logout
pub struct LogoutService {
    // Logout is stateless, no fields needed
}

impl LogoutService {
    /// Create a new logout service
    pub fn new() -> Self {
        Self {}
    }

    /// Handle logout operation
    ///
    /// In a cookie-based authentication system, logout is handled
    /// by removing the authentication cookie. This method exists
    /// for consistency with the application service pattern and
    /// potential future extensions (e.g., token blacklisting,
    /// logging, cleanup operations).
    pub fn logout(&self) {
        // Currently no additional business logic needed for logout
        // The actual cookie removal is handled by the infrastructure layer
    }
}

impl Default for LogoutService {
    fn default() -> Self {
        Self::new()
    }
}
