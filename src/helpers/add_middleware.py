from flask import Flask
from functools import wraps

# custom definition for @app.middleware. Use it as you would @app.route
# If you return something, the request will be stopped and the return value will be sent to the client
# If you return None, the request will continue to the next middleware or route


class FlaskWithMiddleware(Flask):
    def __init__(self, *args, **kwargs):

        self.middlewares = []
        super().__init__(*args, **kwargs)

    def middleware(self, path_prefix: str):
        def middleware_decorator(func):
            self.middlewares.append((path_prefix.lstrip("/"), func))
            return func
        return middleware_decorator

    def route(self, rule: str, **options):
        def route_decorator(func):
            enabled_middlewares = [
                middleware for path_prefix, middleware in self.middlewares if
                rule.lstrip("/").startswith(path_prefix)
            ]

            @wraps(func)
            def wrapper(*args, **kwargs):
                for middleware in enabled_middlewares:
                    result = middleware(*args, **kwargs)
                    if result is not None:
                        return result
                return func(*args, **kwargs)
            return super(FlaskWithMiddleware, self).route(rule, **options)(wrapper)
        return route_decorator
