"""High-entropy strings that are public by design."""

# Stripe publishable keys are meant to be embedded in web pages.
STRIPE_PUBLISHABLE_KEY = "pk_live_51HqTz2KZvW8bXnM4sR7pYcL3dF9gH1jK"

# An SSH *public* key.
DEPLOY_PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq3Vx7pL2mN8kR4tY6wB1cD9fH5jK0sQ user@host"

# The SHA-256 of the empty string, used as a sentinel.
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
