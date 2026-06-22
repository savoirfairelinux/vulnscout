# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from typing import Any, Callable, TypeVar, cast

from flask import Flask
from flask.typing import ResponseReturnValue
from functools import wraps

# custom definition for @app.middleware. Use it as you would @app.route
# If you return something, the request will be stopped and the return value will be sent to the client
# If you return None, the request will continue to the next middleware or route

MiddlewareCallable = Callable[..., ResponseReturnValue | None]
RouteFunc = TypeVar("RouteFunc", bound=Callable[..., Any])


class FlaskWithMiddleware(Flask):
    def __init__(self, *args: Any, **kwargs: Any) -> None:

        self.middlewares: list[tuple[str, MiddlewareCallable]] = []
        self._INT_SCAN_FINISHED: bool = False
        super().__init__(*args, **kwargs)

    def middleware(self, path_prefix: str) -> Callable[[MiddlewareCallable], MiddlewareCallable]:
        def middleware_decorator(func: MiddlewareCallable) -> MiddlewareCallable:
            self.middlewares.append((path_prefix.lstrip("/"), func))
            return func
        return middleware_decorator

    def route(self, rule: str, **options: Any) -> Callable[[RouteFunc], RouteFunc]:
        def route_decorator(func: RouteFunc) -> RouteFunc:
            enabled_middlewares = [
                middleware for path_prefix, middleware in self.middlewares if
                rule.lstrip("/").startswith(path_prefix)
            ]

            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                for middleware in enabled_middlewares:
                    result = middleware(*args, **kwargs)
                    if result is not None:
                        return result
                return func(*args, **kwargs)
            return cast(RouteFunc, super(FlaskWithMiddleware, self).route(rule, **options)(wrapper))
        return route_decorator
