/// Minecraft-style username rules for BeaconAuth.
///
/// Requirements (matches common Minecraft username constraints):
/// - Length: 3..=16
/// - Allowed characters: ASCII letters, digits, underscore
/// - Uniqueness: case-insensitive (handled by storing a normalized `username_lower` in DB)

pub const MINECRAFT_USERNAME_MIN_LEN: usize = 3;
pub const MINECRAFT_USERNAME_MAX_LEN: usize = 16;

pub fn normalize_username(username: &str) -> String {
	username.trim().to_ascii_lowercase()
}

pub fn is_valid_minecraft_username(username: &str) -> bool {
	let u = username.trim();
	let len = u.len();
	if len < MINECRAFT_USERNAME_MIN_LEN || len > MINECRAFT_USERNAME_MAX_LEN {
		return false;
	}

	// Minecraft usernames are effectively ASCII-only.
	if !u.is_ascii() {
		return false;
	}

	u.bytes().all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_'))
}

pub fn validate_minecraft_username(username: &str) -> Result<(), &'static str> {
	if is_valid_minecraft_username(username) {
		Ok(())
	} else {
		Err("Username must be 3-16 characters and contain only letters, numbers, and underscore")
	}
}

/// Sanitizes a raw string into a Minecraft-username-safe fragment (characters only).
///
/// This is intended for deriving an initial placeholder username from OAuth providers.
/// It does NOT enforce length; callers should truncate as needed.
pub fn sanitize_minecraft_username_fragment(raw: &str) -> String {
	let mut out = String::with_capacity(raw.len().min(MINECRAFT_USERNAME_MAX_LEN));

	for ch in raw.chars() {
		if ch.is_ascii_alphanumeric() || ch == '_' {
			out.push(ch);
		} else if matches!(ch, '-' | '.' | ' ' | ':') {
			out.push('_');
		} else {
			// Drop other characters.
		}
	}

	// Avoid empty fragments.
	if out.is_empty() {
		out.push_str("user");
	}

	out
}

/// Build a Minecraft-valid username from a prefix + raw base + optional numeric suffix.
///
/// - `prefix` should already be Minecraft-safe (e.g. "gh_", "gg_")
/// - `attempt` is used to create a deterministic suffix for collision handling.
pub fn make_minecraft_username_with_prefix(prefix: &str, raw_base: &str, attempt: u32) -> String {
	let prefix = prefix.trim();
	let mut base = sanitize_minecraft_username_fragment(raw_base);

	// Ensure prefix is ASCII/valid chars; if not, just fall back to no prefix.
	if !prefix.is_ascii() {
		return make_minecraft_username_with_prefix("", raw_base, attempt);
	}

	let suffix = if attempt == 0 {
		String::new()
	} else {
		// attempt=1 => _2, attempt=2 => _3 ... (so the first collision becomes _2)
		format!("_{}", attempt + 1)
	};

	let max_base_len = MINECRAFT_USERNAME_MAX_LEN
		.saturating_sub(prefix.len())
		.saturating_sub(suffix.len());

	if base.len() > max_base_len {
		base.truncate(max_base_len);
	}

	// If truncation made the base empty, provide a minimal placeholder.
	if base.is_empty() {
		base.push('u');
	}

	let mut candidate = String::with_capacity(prefix.len() + base.len() + suffix.len());
	candidate.push_str(prefix);
	candidate.push_str(&base);
	candidate.push_str(&suffix);

	// Final safety: trim to max len.
	if candidate.len() > MINECRAFT_USERNAME_MAX_LEN {
		candidate.truncate(MINECRAFT_USERNAME_MAX_LEN);
	}

	// Ensure minimum length (should usually be satisfied by prefixes like "gh_").
	while candidate.len() < MINECRAFT_USERNAME_MIN_LEN {
		candidate.push('0');
	}

	// Guarantee it's valid per our checker (should be by construction).
	if !is_valid_minecraft_username(&candidate) {
		// As a last resort, return a known-good placeholder.
		"user_000".to_string()
	} else {
		candidate
	}
}