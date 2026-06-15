# Authentication

How to authenticate requests and authorize them, whichever transport the caller uses.

<div class="grid cards" markdown>

-   **Protecting routes**

    ---

    Gate endpoints with `current_user()` and its keyword guards (superuser, scopes,
    verified, and custom checks).

    [Protecting routes →](protecting-routes.md)

-   **Sessions**

    ---

    Cookie auth, CSRF, remember-me, multi-device management, and the session lifecycle.

    [Sessions →](sessions.md)

-   **Bearer tokens**

    ---

    JWT access and refresh tokens, scopes, and revocation.

    [Bearer tokens →](bearer.md)

-   **Multiple transports**

    ---

    Run sessions and bearer together behind one `Principal`.

    [Multiple transports →](multiple-transports.md)

-   **OAuth**

    ---

    Google, GitHub, and custom providers.

    [OAuth →](oauth.md)

-   **Sudo mode**

    ---

    Short-lived re-authentication for sensitive actions.

    [Sudo mode →](sudo.md)

</div>
