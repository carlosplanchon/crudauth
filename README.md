# crudauth

Batteries-included, transport-agnostic authentication for FastAPI.

One `CRUDAuth` object gives you cookie sessions, JWT bearer tokens, OAuth, email
flows (verify / reset / change), CSRF, login lockout, and multi-device session
management — over **your** SQLAlchemy `User` model, with app policy in hooks
instead of forked dependency code.

> Status: early `0.1` — the API is the v1 surface we're converging on.

## Install

```bash
pip install crudauth            # core (session + bearer)
pip install "crudauth[all]"     # + httpx (oauth), redis, user-agents
```

## Quickstart

Sessions are the default — no `transports=` needed. You get cookie auth, CSRF,
login lockout, secure cookies, and `/login` `/logout` `/register` `/me`.

```python
from fastapi import FastAPI, Depends
from crudauth import CRUDAuth, Principal
from myapp.db import get_session
from myapp.models import User

auth = CRUDAuth(session=get_session, user_model=User, SECRET_KEY="change-me")

app = FastAPI()
app.include_router(auth.router)

@app.get("/dashboard")
async def dashboard(me: Principal = Depends(auth.current_user())):
    return {"hello": me.user.username}
```

## The user model

Inherit the mixin and get every column the package needs; your own columns
coexist freely.

```python
from sqlalchemy.orm import Mapped, mapped_column
from crudauth.models import AuthUserMixin
from myapp.db import Base

class User(Base, AuthUserMixin):
    __tablename__ = "users"
    full_name: Mapped[str | None] = mapped_column(default=None)
```

Existing table with different names? Map the contract, don't rename your schema:

```python
auth = CRUDAuth(
    session=get_session, user_model=LegacyAccount, SECRET_KEY=...,
    column_map={"id": "account_id", "email": "email_address", "hashed_password": "pw_hash"},
)
```

## Protecting routes — one factory, every case a kwarg

```python
auth.current_user()                              # required, 401 if anon
auth.current_user(optional=True)                 # None instead of raising
auth.current_user(superuser=True)                # 403 unless is_superuser
auth.current_user(verified=True)                 # 403 unless email_verified
auth.current_user(scopes=["reports:read"])       # 403 unless scopes ⊇ required
auth.current_user(transport="bearer")            # narrow to one transport
auth.current_user(superuser=True, check=my_predicate)  # extra per-route check
```

The resolved `Principal` carries `user_id`, `is_superuser`, `scopes`,
`transport` (which transport authed the request), and `user` (your resolved
row).

## Multiple transports, one identity

```python
from crudauth import CRUDAuth, SessionTransport, BearerTransport

auth = CRUDAuth(
    session=get_session, user_model=User, SECRET_KEY=...,
    transports=[
        SessionTransport(backend="redis", redis_url=..., csrf=True),  # browsers
        BearerTransport(access_ttl=900, refresh="cookie"),            # apps/scripts
    ],
)
```

When both credentials are present, the **first transport in the list wins**.
CSRF is a property of the session transport — it appears only where sessions do,
never on bearer/api-key paths.

## Storage & lifespan

Server-side backends open connections and run a cleanup sweep — call
`initialize()` / `shutdown()` in your lifespan:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    await auth.initialize()
    yield
    await auth.shutdown()
```

## OAuth, email, hooks

See the usage cookbook for OAuth (Google/GitHub/custom providers), email flows
(implement the `EmailSender` port; the package mints/verifies the signed
tokens), lifecycle hooks (`AuthHooks` — welcome email, trial grant, audit log),
and dropping to primitives.

## License

MIT
