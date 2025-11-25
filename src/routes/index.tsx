import { createFileRoute, Link } from '@tanstack/react-router';

function HomePage() {
  return (
    <div className="min-h-screen bg-linear-to-br from-indigo-100 via-purple-50 to-pink-100">
      {/* Hero Section */}
      <div className="container mx-auto px-4 py-16">
        <div className="text-center mb-16">
          <div className="text-7xl mb-6">🔐</div>
          <h1 className="text-5xl font-bold text-gray-900 mb-6">
            BeaconAuth
          </h1>
          <p className="text-xl text-gray-600 mb-8 max-w-2xl mx-auto">
            Modern, secure authentication for Minecraft servers with support for
            password, OAuth, and passkey authentication.
          </p>
          <div className="flex gap-4 justify-center">
            <Link
              to="/login"
              className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium"
            >
              Login
            </Link>
            <Link
              to="/register"
              className="px-6 py-3 bg-white text-blue-600 border-2 border-blue-600 rounded-lg hover:bg-blue-50 transition-colors font-medium"
            >
              Register
            </Link>
            <Link
              to="/profile"
              className="px-6 py-3 bg-white text-gray-900 border-2 border-gray-300 rounded-lg hover:bg-gray-50 transition-colors font-medium"
            >
              Profile
            </Link>
            <a
              href="https://github.com/Summpot/beacon_auth"
              target="_blank"
              rel="noopener noreferrer"
              className="px-6 py-3 bg-gray-900 text-white rounded-lg hover:bg-gray-800 transition-colors font-medium"
            >
              GitHub →
            </a>
          </div>
        </div>

        {/* Features Grid */}
        <div className="grid md:grid-cols-3 gap-8 max-w-6xl mx-auto">
          {/* Feature 1 */}
          <div className="bg-white rounded-xl p-8 shadow-lg">
            <div className="text-4xl mb-4">🔑</div>
            <h3 className="text-xl font-bold text-gray-900 mb-3">
              Multiple Auth Methods
            </h3>
            <p className="text-gray-600">
              Support for traditional passwords, OAuth (GitHub/Google), and modern
              WebAuthn passkeys for enhanced security.
            </p>
          </div>

          {/* Feature 2 */}
          <div className="bg-white rounded-xl p-8 shadow-lg">
            <div className="text-4xl mb-4">🛡️</div>
            <h3 className="text-xl font-bold text-gray-900 mb-3">
              Enterprise-Grade Security
            </h3>
            <p className="text-gray-600">
              ES256 JWT signing, secure HTTP-only cookies, refresh token
              rotation, and PKCE for OAuth flows.
            </p>
          </div>

          {/* Feature 3 */}
          <div className="bg-white rounded-xl p-8 shadow-lg">
            <div className="text-4xl mb-4">🎮</div>
            <h3 className="text-xl font-bold text-gray-900 mb-3">
              Seamless Minecraft Integration
            </h3>
            <p className="text-gray-600">
              Cross-platform mod (Fabric/Forge) with automatic authentication
              flow and server-side verification.
            </p>
          </div>
        </div>

        {/* Tech Stack */}
        <div className="mt-16 max-w-4xl mx-auto">
          <h2 className="text-3xl font-bold text-center text-gray-900 mb-8">
            Built With Modern Technologies
          </h2>
          <div className="bg-white rounded-xl p-8 shadow-lg">
            <div className="grid md:grid-cols-2 gap-6">
              <div>
                <h4 className="font-bold text-gray-900 mb-3">Backend</h4>
                <ul className="space-y-2 text-gray-600">
                  <li>• Rust with Actix-web</li>
                  <li>• Sea-ORM for database management</li>
                  <li>• ES256 JWT signing</li>
                  <li>• WebAuthn for passkey support</li>
                </ul>
              </div>
              <div>
                <h4 className="font-bold text-gray-900 mb-3">Frontend & Mod</h4>
                <ul className="space-y-2 text-gray-600">
                  <li>• React with TanStack Router</li>
                  <li>• Rsbuild for fast bundling</li>
                  <li>• Kotlin Architectury mod</li>
                  <li>• Multi-loader support (Fabric/Forge)</li>
                </ul>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="mt-16 text-center text-gray-600">
          <p className="mb-2">Open source and built with ❤️</p>
          <p className="text-sm">
            Licensed under MIT • Contributions welcome
          </p>
        </div>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/')({
  component: HomePage,
});
